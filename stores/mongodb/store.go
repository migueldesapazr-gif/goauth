// Package mongodb provides a MongoDB implementation of the goauth.Store interface.
package mongodb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"login"
)

// Store implements goauth.Store for MongoDB.
type Store struct {
	db                 *mongo.Database
	users              *mongo.Collection
	passwordHistory    *mongo.Collection
	backupCodes        *mongo.Collection
	verificationTokens *mongo.Collection
	resetTokens        *mongo.Collection
	refreshTokens      *mongo.Collection
	magicTokens        *mongo.Collection
	emailChangeTokens  *mongo.Collection
	auditLogs          *mongo.Collection
	oauthConnections   *mongo.Collection
	profiles           *mongo.Collection
}

// New creates a new MongoDB store.
func New(client *mongo.Client, dbName string) *Store {
	db := client.Database(dbName)
	s := &Store{
		db:                 db,
		users:              db.Collection("users"),
		passwordHistory:    db.Collection("password_history"),
		backupCodes:        db.Collection("totp_backup_codes"),
		verificationTokens: db.Collection("email_verification_tokens"),
		resetTokens:        db.Collection("password_reset_tokens"),
		refreshTokens:      db.Collection("refresh_tokens"),
		magicTokens:        db.Collection("magic_link_tokens"),
		emailChangeTokens:  db.Collection("email_change_tokens"),
		auditLogs:          db.Collection("audit_logs"),
		oauthConnections:   db.Collection("oauth_connections"),
		profiles:           db.Collection("profiles"),
	}
	s.ensureIndexes(context.Background())
	return s
}

func (s *Store) ensureIndexes(ctx context.Context) {
	_, _ = s.users.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "email_hash", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "username_normalized", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "account_status", Value: 1}}},
		{Keys: bson.D{{Key: "verification_deadline", Value: 1}}},
	})
	_, _ = s.refreshTokens.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "jti", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	_, _ = s.emailChangeTokens.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "token_hash", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	_, _ = s.oauthConnections.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "provider", Value: 1}, {Key: "provider_user_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	_, _ = s.profiles.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "user_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
}

// Users returns the user store.
func (s *Store) Users() goauth.UserStore {
	return &UserStore{store: s}
}

// Tokens returns the token store.
func (s *Store) Tokens() goauth.TokenStore {
	return &TokenStore{store: s}
}

// Audit returns the audit store.
func (s *Store) Audit() goauth.AuditStore {
	return &AuditStore{store: s}
}

// Profiles returns the profile store.
func (s *Store) Profiles() goauth.ProfileStore {
	return &ProfileStore{store: s}
}

// GetUserByOAuthProvider returns a user linked to an OAuth provider.
func (s *Store) GetUserByOAuthProvider(ctx context.Context, provider, providerUserID string) (*goauth.User, error) {
	var conn struct {
		UserID string `bson:"user_id"`
	}
	err := s.oauthConnections.FindOne(ctx, bson.M{
		"provider":         provider,
		"provider_user_id": providerUserID,
	}).Decode(&conn)
	if err != nil {
		return nil, err
	}
	return s.Users().GetUserByID(ctx, conn.UserID)
}

// LinkOAuthConnection links a user to an OAuth provider.
func (s *Store) LinkOAuthConnection(ctx context.Context, userID, provider, providerUserID string) error {
	_, err := s.oauthConnections.InsertOne(ctx, bson.M{
		"_id":             uuid.NewString(),
		"user_id":         userID,
		"provider":        provider,
		"provider_user_id": providerUserID,
		"created_at":      time.Now(),
		"updated_at":      time.Now(),
	})
	return err
}

// UnlinkOAuthConnection removes a provider link for a user.
func (s *Store) UnlinkOAuthConnection(ctx context.Context, userID, provider string) error {
	_, err := s.oauthConnections.DeleteOne(ctx, bson.M{
		"user_id":  userID,
		"provider": provider,
	})
	return err
}

// GetUserOAuthConnections lists OAuth connections for a user.
func (s *Store) GetUserOAuthConnections(ctx context.Context, userID string) ([]goauth.OAuthConnection, error) {
	cursor, err := s.oauthConnections.Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var out []goauth.OAuthConnection
	for cursor.Next(ctx) {
		var doc struct {
			ID         string    `bson:"_id"`
			Provider   string    `bson:"provider"`
			ProviderID string    `bson:"provider_user_id"`
			CreatedAt  time.Time `bson:"created_at"`
		}
		if err := cursor.Decode(&doc); err != nil {
			return nil, err
		}
		out = append(out, goauth.OAuthConnection{
			ID:         doc.ID,
			UserID:     userID,
			Provider:   doc.Provider,
			ProviderID: doc.ProviderID,
			CreatedAt:  doc.CreatedAt,
		})
	}
	return out, nil
}

// StoreOAuthTokens stores encrypted OAuth tokens for a user/provider.
func (s *Store) StoreOAuthTokens(ctx context.Context, userID, provider string, accessEnc, accessNonce, refreshEnc, refreshNonce []byte, expiresAt time.Time) error {
	_, err := s.oauthConnections.UpdateOne(ctx, bson.M{
		"user_id":  userID,
		"provider": provider,
	}, bson.M{
		"$set": bson.M{
			"access_token_encrypted":  accessEnc,
			"access_token_nonce":      accessNonce,
			"refresh_token_encrypted": refreshEnc,
			"refresh_token_nonce":     refreshNonce,
			"token_expires_at":        expiresAt,
			"updated_at":              time.Now(),
		},
	})
	return err
}

// GetOAuthTokens retrieves encrypted OAuth tokens for a user/provider.
func (s *Store) GetOAuthTokens(ctx context.Context, userID, provider string) (accessEnc, accessNonce, refreshEnc, refreshNonce []byte, expiresAt time.Time, err error) {
	var doc struct {
		AccessEnc  []byte    `bson:"access_token_encrypted"`
		AccessNonce []byte   `bson:"access_token_nonce"`
		RefreshEnc []byte    `bson:"refresh_token_encrypted"`
		RefreshNonce []byte  `bson:"refresh_token_nonce"`
		ExpiresAt  time.Time `bson:"token_expires_at"`
	}
	err = s.oauthConnections.FindOne(ctx, bson.M{"user_id": userID, "provider": provider}).Decode(&doc)
	if err != nil {
		return nil, nil, nil, nil, time.Time{}, err
	}
	return doc.AccessEnc, doc.AccessNonce, doc.RefreshEnc, doc.RefreshNonce, doc.ExpiresAt, nil
}

// DeleteOAuthTokens clears stored OAuth tokens for a user/provider.
func (s *Store) DeleteOAuthTokens(ctx context.Context, userID, provider string) error {
	_, err := s.oauthConnections.UpdateOne(ctx, bson.M{
		"user_id":  userID,
		"provider": provider,
	}, bson.M{
		"$set": bson.M{
			"access_token_encrypted":  nil,
			"access_token_nonce":      nil,
			"refresh_token_encrypted": nil,
			"refresh_token_nonce":     nil,
			"token_expires_at":        time.Time{},
			"updated_at":              time.Now(),
		},
	})
	return err
}

// CleanupExpiredTokens removes all expired tokens.
func (s *Store) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	now := time.Now()
	var total int64

	if res, err := s.verificationTokens.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lt": now}}); err == nil {
		total += res.DeletedCount
	}
	if res, err := s.resetTokens.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lt": now}}); err == nil {
		total += res.DeletedCount
	}
	if res, err := s.refreshTokens.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lt": now}}); err == nil {
		total += res.DeletedCount
	}
	if res, err := s.magicTokens.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lt": now}}); err == nil {
		total += res.DeletedCount
	}
	if res, err := s.emailChangeTokens.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lt": now}}); err == nil {
		total += res.DeletedCount
	}

	return total, nil
}

// CleanupOldAuditLogs removes audit logs older than retention period.
func (s *Store) CleanupOldAuditLogs(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention)
	res, err := s.auditLogs.DeleteMany(ctx, bson.M{"created_at": bson.M{"$lt": cutoff}})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

// CleanupUnverifiedAccounts removes unverified accounts past deadline.
func (s *Store) CleanupUnverifiedAccounts(ctx context.Context) (int64, error) {
	now := time.Now()
	res, err := s.users.DeleteMany(ctx, bson.M{
		"email_verified":        false,
		"verification_deadline": bson.M{"$lt": now},
	})
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

// DeleteUser removes all user data (GDPR compliance).
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	collections := []*mongo.Collection{
		s.backupCodes,
		s.refreshTokens,
		s.verificationTokens,
		s.resetTokens,
		s.emailChangeTokens,
		s.passwordHistory,
		s.magicTokens,
		s.profiles,
		s.oauthConnections,
		s.auditLogs,
	}
	for _, col := range collections {
		_, _ = col.DeleteMany(ctx, bson.M{"user_id": userID})
	}
	_, err := s.users.DeleteOne(ctx, bson.M{"_id": userID})
	return err
}

// ExportUserData exports all user data as JSON (GDPR compliance).
func (s *Store) ExportUserData(ctx context.Context, userID string) ([]byte, error) {
	data := make(map[string]any)

	user, err := s.Users().GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	data["user"] = map[string]any{
		"id":             user.ID,
		"email_verified": user.EmailVerified,
		"totp_enabled":   user.TOTPEnabled,
		"account_status": user.AccountStatus,
		"role":           user.Role,
		"created_at":     user.CreatedAt,
		"last_login_at":  user.LastLoginAt,
	}

	profile, err := s.Profiles().GetProfile(ctx, userID)
	if err == nil && profile != nil {
		data["profile"] = profile
	}

	cursor, _ := s.auditLogs.Find(ctx, bson.M{"user_id": userID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(100))
	var logs []map[string]any
	for cursor.Next(ctx) {
		var entry struct {
			EventType string    `bson:"event_type"`
			CreatedAt time.Time `bson:"created_at"`
		}
		_ = cursor.Decode(&entry)
		logs = append(logs, map[string]any{"event": entry.EventType, "timestamp": entry.CreatedAt})
	}
	data["audit_logs"] = logs

	return json.Marshal(data)
}

// ExportUserAuditLogs exports user audit logs.
func (s *Store) ExportUserAuditLogs(ctx context.Context, userID, format string) ([]byte, error) {
	cursor, err := s.auditLogs.Find(ctx, bson.M{"user_id": userID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []map[string]any
	for cursor.Next(ctx) {
		var entry struct {
			ID        string    `bson:"_id"`
			EventType string    `bson:"event_type"`
			CreatedAt time.Time `bson:"created_at"`
		}
		_ = cursor.Decode(&entry)
		logs = append(logs, map[string]any{"id": entry.ID, "event": entry.EventType, "timestamp": entry.CreatedAt})
	}

	if format == "csv" {
		var buf bytes.Buffer
		buf.WriteString("id,event,timestamp\n")
		for _, log := range logs {
			buf.WriteString(fmt.Sprintf("%s,%s,%s\n", log["id"], log["event"], log["timestamp"]))
		}
		return buf.Bytes(), nil
	}

	return json.Marshal(logs)
}

// ==================== USER STORE ====================

type UserStore struct {
	store *Store
}

func (s *UserStore) EmailExists(ctx context.Context, emailHash []byte) (bool, error) {
	count, err := s.store.users.CountDocuments(ctx, bson.M{"email_hash": emailHash})
	return count > 0, err
}

func (s *UserStore) UsernameExists(ctx context.Context, usernameNormalized string) (bool, error) {
	if usernameNormalized == "" {
		return false, nil
	}
	count, err := s.store.users.CountDocuments(ctx, bson.M{"username_normalized": usernameNormalized})
	return count > 0, err
}

func (s *UserStore) CreateUser(ctx context.Context, user goauth.User, verificationDeadline time.Time) (string, error) {
	userID := user.ID
	if userID == "" {
		userID = uuid.NewString()
	}
	doc := bson.M{
		"_id":                  userID,
		"email_hash":           user.EmailHash,
		"email_encrypted":      user.EmailEncrypted,
		"email_nonce":          user.EmailNonce,
		"password_hash":        user.PasswordHash,
		"password_salt":        user.PasswordSalt,
		"totp_secret_encrypted": user.TOTPSecretEncrypted,
		"totp_nonce":           user.TOTPNonce,
		"totp_enabled":         user.TOTPEnabled,
		"email_verified":       user.EmailVerified,
		"account_status":       user.AccountStatus,
		"role":                 user.Role,
		"failed_login_attempts": user.FailedLoginAttempts,
		"created_at":           time.Now(),
		"updated_at":           time.Now(),
	}
	if !verificationDeadline.IsZero() {
		doc["verification_deadline"] = verificationDeadline
	}
	if user.Username != "" {
		doc["username"] = user.Username
	}
	if user.UsernameNormalized != "" {
		doc["username_normalized"] = user.UsernameNormalized
	}
	_, err := s.store.users.InsertOne(ctx, doc)
	if err != nil {
		return "", err
	}

	if user.PasswordHash != nil && user.PasswordSalt != nil {
		_, _ = s.store.passwordHistory.InsertOne(ctx, bson.M{
			"_id":          uuid.NewString(),
			"user_id":      userID,
			"password_hash": user.PasswordHash,
			"password_salt": user.PasswordSalt,
			"created_at":   time.Now(),
		})
	}

	return userID, nil
}

func (s *UserStore) GetUserByEmailHash(ctx context.Context, emailHash []byte) (*goauth.User, error) {
	var doc bson.M
	err := s.store.users.FindOne(ctx, bson.M{"email_hash": emailHash}).Decode(&doc)
	if err != nil {
		return nil, err
	}
	return decodeUser(doc), nil
}

func (s *UserStore) GetUserByUsername(ctx context.Context, usernameNormalized string) (*goauth.User, error) {
	var doc bson.M
	err := s.store.users.FindOne(ctx, bson.M{"username_normalized": usernameNormalized}).Decode(&doc)
	if err != nil {
		return nil, err
	}
	return decodeUser(doc), nil
}

func (s *UserStore) GetUserByID(ctx context.Context, userID string) (*goauth.User, error) {
	var doc bson.M
	err := s.store.users.FindOne(ctx, bson.M{"_id": userID}).Decode(&doc)
	if err != nil {
		return nil, err
	}
	return decodeUser(doc), nil
}

func (s *UserStore) SetUserVerified(ctx context.Context, userID string) error {
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{
			"email_verified":       true,
			"account_status":       "active",
			"email_verified_at":    time.Now(),
			"verification_deadline": nil,
			"updated_at":           time.Now(),
		},
	})
	return err
}

func (s *UserStore) IncrementLoginFailures(ctx context.Context, userID string) (int, error) {
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var doc bson.M
	err := s.store.users.FindOneAndUpdate(ctx, bson.M{"_id": userID}, bson.M{
		"$inc": bson.M{"failed_login_attempts": 1},
		"$set": bson.M{"updated_at": time.Now()},
	}, opts).Decode(&doc)
	if err != nil {
		return 0, err
	}
	if v, ok := doc["failed_login_attempts"].(int32); ok {
		return int(v), nil
	}
	if v, ok := doc["failed_login_attempts"].(int64); ok {
		return int(v), nil
	}
	return 0, nil
}

func (s *UserStore) LockUser(ctx context.Context, userID string) error {
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{
			"account_status": "locked",
			"locked_at":      time.Now(),
			"updated_at":     time.Now(),
		},
	})
	return err
}

func (s *UserStore) UnlockUser(ctx context.Context, userID string) error {
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{
			"account_status": "active",
			"locked_at":      nil,
			"updated_at":     time.Now(),
		},
	})
	return err
}

func (s *UserStore) ResetLoginFailures(ctx context.Context, userID string) error {
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{"failed_login_attempts": 0, "updated_at": time.Now()},
	})
	return err
}

func (s *UserStore) UpdateLastLogin(ctx context.Context, userID string, ipEnc, ipNonce []byte) error {
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{
			"last_login_at":          time.Now(),
			"last_login_ip_encrypted": ipEnc,
			"last_login_ip_nonce":     ipNonce,
			"updated_at":             time.Now(),
		},
	})
	return err
}

func (s *UserStore) UpdateUsername(ctx context.Context, userID, username, usernameNormalized string) error {
	update := bson.M{
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}
	if username == "" || usernameNormalized == "" {
		update["$unset"] = bson.M{
			"username":            "",
			"username_normalized": "",
		}
	} else {
		update["$set"].(bson.M)["username"] = username
		update["$set"].(bson.M)["username_normalized"] = usernameNormalized
	}
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

func (s *UserStore) UpdatePassword(ctx context.Context, userID string, hash, salt []byte) error {
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{
			"password_hash": hash,
			"password_salt": salt,
			"updated_at":    time.Now(),
		},
	})
	if err != nil {
		return err
	}
	_, _ = s.store.passwordHistory.InsertOne(ctx, bson.M{
		"_id":          uuid.NewString(),
		"user_id":      userID,
		"password_hash": hash,
		"password_salt": salt,
		"created_at":   time.Now(),
	})
	return nil
}

func (s *UserStore) UpdateEmail(ctx context.Context, userID string, emailHash, emailEnc, emailNonce []byte, verified bool) error {
	update := bson.M{
		"email_hash":      emailHash,
		"email_encrypted": emailEnc,
		"email_nonce":     emailNonce,
		"email_verified":  verified,
		"updated_at":      time.Now(),
	}
	if verified {
		update["email_verified_at"] = time.Now()
		update["account_status"] = "active"
	}
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{"$set": update})
	return err
}

func (s *UserStore) RecentPasswordHistory(ctx context.Context, userID string, limit int) ([]goauth.PasswordHistory, error) {
	cursor, err := s.store.passwordHistory.Find(ctx, bson.M{"user_id": userID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var history []goauth.PasswordHistory
	for cursor.Next(ctx) {
		var entry struct {
			Hash []byte `bson:"password_hash"`
			Salt []byte `bson:"password_salt"`
		}
		_ = cursor.Decode(&entry)
		history = append(history, goauth.PasswordHistory{Hash: entry.Hash, Salt: entry.Salt})
	}
	return history, nil
}

func (s *UserStore) UpdateTOTPSecret(ctx context.Context, userID string, secretEnc, secretNonce []byte) error {
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{
			"totp_secret_encrypted": secretEnc,
			"totp_nonce":           secretNonce,
			"updated_at":           time.Now(),
		},
	})
	return err
}

func (s *UserStore) EnableTOTP(ctx context.Context, userID string) error {
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{
			"totp_enabled":     true,
			"totp_verified_at": time.Now(),
			"updated_at":       time.Now(),
		},
	})
	return err
}

func (s *UserStore) DisableTOTP(ctx context.Context, userID string) error {
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{
			"totp_enabled":         false,
			"totp_secret_encrypted": nil,
			"totp_nonce":           nil,
			"totp_verified_at":     nil,
			"updated_at":           time.Now(),
		},
	})
	if err != nil {
		return err
	}
	_, _ = s.store.backupCodes.DeleteMany(ctx, bson.M{"user_id": userID})
	return nil
}

func (s *UserStore) ReplaceBackupCodes(ctx context.Context, userID string, hashes [][]byte) error {
	_, _ = s.store.backupCodes.DeleteMany(ctx, bson.M{"user_id": userID})
	var docs []any
	now := time.Now()
	for _, hash := range hashes {
		docs = append(docs, bson.M{
			"_id":       uuid.NewString(),
			"user_id":   userID,
			"code_hash": hash,
			"used":      false,
			"created_at": now,
		})
	}
	if len(docs) == 0 {
		return nil
	}
	_, err := s.store.backupCodes.InsertMany(ctx, docs)
	return err
}

func (s *UserStore) UseBackupCode(ctx context.Context, userID string, codeHash []byte) (bool, error) {
	res, err := s.store.backupCodes.UpdateOne(ctx, bson.M{
		"user_id":  userID,
		"code_hash": codeHash,
		"used":     false,
	}, bson.M{
		"$set": bson.M{"used": true, "used_at": time.Now()},
	})
	if err != nil {
		return false, err
	}
	return res.ModifiedCount > 0, nil
}

func (s *UserStore) UpdateUserRole(ctx context.Context, userID string, role string) error {
	_, err := s.store.users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{"role": role, "updated_at": time.Now()},
	})
	return err
}

// ==================== PROFILE STORE ====================

type ProfileStore struct {
	store *Store
}

func (s *ProfileStore) GetProfile(ctx context.Context, userID string) (*goauth.Profile, error) {
	var doc bson.M
	err := s.store.profiles.FindOne(ctx, bson.M{"user_id": userID}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, goauth.ErrProfileNotFound
	}
	if err != nil {
		return nil, err
	}
	return decodeProfile(doc), nil
}

func (s *ProfileStore) UpsertProfile(ctx context.Context, profile goauth.Profile) error {
	doc := bson.M{
		"user_id":          profile.UserID,
		"display_name":     profile.DisplayName,
		"display_photo_url": profile.DisplayPhotoURL,
		"bio":              profile.Bio,
		"locale":           profile.Locale,
		"timezone":         profile.Timezone,
		"metadata":         profile.Metadata,
		"updated_at":       time.Now(),
	}
	_, err := s.store.profiles.UpdateOne(ctx, bson.M{"user_id": profile.UserID}, bson.M{
		"$set":         doc,
		"$setOnInsert": bson.M{"created_at": time.Now()},
	}, options.Update().SetUpsert(true))
	return err
}

func (s *ProfileStore) DeleteProfile(ctx context.Context, userID string) error {
	_, err := s.store.profiles.DeleteOne(ctx, bson.M{"user_id": userID})
	return err
}

// ==================== TOKEN STORE ====================

type TokenStore struct {
	store *Store
}

func (s *TokenStore) CreateVerificationToken(ctx context.Context, token goauth.VerificationToken, ipEnc, ipNonce []byte) (string, error) {
	_, _ = s.store.verificationTokens.UpdateMany(ctx, bson.M{"user_id": token.UserID, "used": false}, bson.M{
		"$set": bson.M{"used": true, "used_at": time.Now()},
	})
	id := uuid.NewString()
	_, err := s.store.verificationTokens.InsertOne(ctx, bson.M{
		"_id":               id,
		"user_id":           token.UserID,
		"code_hash":         token.CodeHash,
		"link_token_hash":   token.LinkHash,
		"email_hash":        token.EmailHash,
		"expires_at":        token.ExpiresAt,
		"code_attempts":     token.CodeAttempts,
		"max_code_attempts": token.MaxAttempts,
		"used":              false,
		"ip_created_encrypted": ipEnc,
		"ip_created_nonce":     ipNonce,
		"created_at":        time.Now(),
	})
	return id, err
}

func (s *TokenStore) GetActiveVerificationToken(ctx context.Context, userID string) (*goauth.VerificationToken, error) {
	opts := options.FindOne().SetSort(bson.D{{Key: "created_at", Value: -1}})
	var doc bson.M
	err := s.store.verificationTokens.FindOne(ctx, bson.M{"user_id": userID, "used": false}, opts).Decode(&doc)
	if err != nil {
		return nil, err
	}
	return decodeVerificationToken(doc), nil
}

func (s *TokenStore) GetVerificationTokenByLinkHash(ctx context.Context, linkHash []byte) (*goauth.VerificationToken, error) {
	var doc bson.M
	err := s.store.verificationTokens.FindOne(ctx, bson.M{"link_token_hash": linkHash}).Decode(&doc)
	if err != nil {
		return nil, err
	}
	return decodeVerificationToken(doc), nil
}

func (s *TokenStore) IncrementVerificationAttempts(ctx context.Context, tokenID string) (int, error) {
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var doc bson.M
	err := s.store.verificationTokens.FindOneAndUpdate(ctx, bson.M{"_id": tokenID}, bson.M{
		"$inc": bson.M{"code_attempts": 1},
	}, opts).Decode(&doc)
	if err != nil {
		return 0, err
	}
	if v, ok := doc["code_attempts"].(int32); ok {
		return int(v), nil
	}
	if v, ok := doc["code_attempts"].(int64); ok {
		return int(v), nil
	}
	return 0, nil
}

func (s *TokenStore) MarkVerificationTokenUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error {
	_, err := s.store.verificationTokens.UpdateOne(ctx, bson.M{"_id": tokenID}, bson.M{
		"$set": bson.M{
			"used":            true,
			"used_at":         time.Now(),
			"ip_used_encrypted": ipEnc,
			"ip_used_nonce":     ipNonce,
		},
	})
	return err
}

func (s *TokenStore) CreatePasswordResetToken(ctx context.Context, token goauth.PasswordResetToken, ipEnc, ipNonce []byte) (string, error) {
	id := uuid.NewString()
	_, err := s.store.resetTokens.InsertOne(ctx, bson.M{
		"_id":               id,
		"user_id":           token.UserID,
		"token_hash":        token.TokenHash,
		"expires_at":        token.ExpiresAt,
		"used":              false,
		"ip_request_encrypted": ipEnc,
		"ip_request_nonce":     ipNonce,
		"created_at":        time.Now(),
	})
	return id, err
}

func (s *TokenStore) GetPasswordResetTokenByHash(ctx context.Context, tokenHash []byte) (*goauth.PasswordResetToken, error) {
	var doc bson.M
	err := s.store.resetTokens.FindOne(ctx, bson.M{"token_hash": tokenHash}).Decode(&doc)
	if err != nil {
		return nil, err
	}
	return decodePasswordResetToken(doc), nil
}

func (s *TokenStore) MarkPasswordResetUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error {
	_, err := s.store.resetTokens.UpdateOne(ctx, bson.M{"_id": tokenID}, bson.M{
		"$set": bson.M{
			"used":           true,
			"used_at":        time.Now(),
			"ip_used_encrypted": ipEnc,
			"ip_used_nonce":     ipNonce,
		},
	})
	return err
}

func (s *TokenStore) CreateEmailChangeToken(ctx context.Context, token goauth.EmailChangeToken, ipEnc, ipNonce []byte) (string, error) {
	id := uuid.NewString()
	_, err := s.store.emailChangeTokens.InsertOne(ctx, bson.M{
		"_id":                 id,
		"user_id":             token.UserID,
		"token_hash":          token.TokenHash,
		"new_email_hash":      token.NewEmailHash,
		"new_email_encrypted": token.NewEmailEncrypted,
		"new_email_nonce":     token.NewEmailNonce,
		"expires_at":          token.ExpiresAt,
		"used":                false,
		"ip_created_encrypted": ipEnc,
		"ip_created_nonce":     ipNonce,
		"created_at":          time.Now(),
	})
	return id, err
}

func (s *TokenStore) GetEmailChangeTokenByHash(ctx context.Context, tokenHash []byte) (*goauth.EmailChangeToken, error) {
	var doc bson.M
	err := s.store.emailChangeTokens.FindOne(ctx, bson.M{"token_hash": tokenHash}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, errors.New("token not found")
	}
	if err != nil {
		return nil, err
	}
	token := &goauth.EmailChangeToken{
		ID:                asString(doc["_id"]),
		UserID:            asString(doc["user_id"]),
		TokenHash:         asBytes(doc["token_hash"]),
		NewEmailHash:      asBytes(doc["new_email_hash"]),
		NewEmailEncrypted: asBytes(doc["new_email_encrypted"]),
		NewEmailNonce:     asBytes(doc["new_email_nonce"]),
		Used:              asBool(doc["used"]),
	}
	if v, ok := doc["expires_at"].(time.Time); ok {
		token.ExpiresAt = v
	}
	return token, nil
}

func (s *TokenStore) MarkEmailChangeUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error {
	_, err := s.store.emailChangeTokens.UpdateOne(ctx, bson.M{"_id": tokenID}, bson.M{
		"$set": bson.M{
			"used":           true,
			"used_at":        time.Now(),
			"ip_used_encrypted": ipEnc,
			"ip_used_nonce":     ipNonce,
		},
	})
	return err
}

func (s *TokenStore) StoreRefreshToken(ctx context.Context, userID, jti string, expiresAt time.Time, ipEnc, ipNonce []byte) error {
	_, err := s.store.refreshTokens.InsertOne(ctx, bson.M{
		"_id":         uuid.NewString(),
		"jti":         jti,
		"user_id":     userID,
		"expires_at":  expiresAt,
		"revoked_at":  nil,
		"ip_encrypted": ipEnc,
		"ip_nonce":     ipNonce,
		"created_at":  time.Now(),
	})
	return err
}

func (s *TokenStore) RefreshTokenValid(ctx context.Context, jti string) (bool, error) {
	now := time.Now()
	count, err := s.store.refreshTokens.CountDocuments(ctx, bson.M{
		"jti":        jti,
		"revoked_at": nil,
		"expires_at": bson.M{"$gt": now},
	})
	return count > 0, err
}

func (s *TokenStore) RevokeRefreshToken(ctx context.Context, jti string) error {
	_, err := s.store.refreshTokens.UpdateOne(ctx, bson.M{"jti": jti}, bson.M{
		"$set": bson.M{"revoked_at": time.Now()},
	})
	return err
}

func (s *TokenStore) RevokeAllRefreshTokens(ctx context.Context, userID string) error {
	_, err := s.store.refreshTokens.UpdateMany(ctx, bson.M{"user_id": userID, "revoked_at": nil}, bson.M{
		"$set": bson.M{"revoked_at": time.Now()},
	})
	return err
}

// ==================== AUDIT STORE ====================

type AuditStore struct {
	store *Store
}

func (s *AuditStore) InsertAuditLog(ctx context.Context, log goauth.AuditLog) error {
	_, err := s.store.auditLogs.InsertOne(ctx, bson.M{
		"_id":             uuid.NewString(),
		"user_id":         log.UserID,
		"event_type":      log.EventType,
		"ip_encrypted":    log.IPEncrypted,
		"ip_nonce":        log.IPNonce,
		"user_agent_hash": log.UserAgentHash,
		"metadata_encrypted": log.MetadataEnc,
		"metadata_nonce":    log.MetadataNonce,
		"expires_at":      log.ExpiresAt,
		"created_at":      time.Now(),
	})
	return err
}

func (s *AuditStore) GetUserAuditLogs(ctx context.Context, userID string, limit int) ([]goauth.AuditLog, error) {
	cursor, err := s.store.auditLogs.Find(ctx, bson.M{"user_id": userID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []goauth.AuditLog
	for cursor.Next(ctx) {
		var entry goauth.AuditLog
		_ = cursor.Decode(&entry)
		logs = append(logs, entry)
	}
	return logs, nil
}

// ==================== HELPERS ====================

func decodeUser(doc bson.M) *goauth.User {
	user := &goauth.User{
		ID:              asString(doc["_id"]),
		EmailHash:       asBytes(doc["email_hash"]),
		EmailEncrypted:  asBytes(doc["email_encrypted"]),
		EmailNonce:      asBytes(doc["email_nonce"]),
		Username:        asString(doc["username"]),
		UsernameNormalized: asString(doc["username_normalized"]),
		PasswordHash:    asBytes(doc["password_hash"]),
		PasswordSalt:    asBytes(doc["password_salt"]),
		TOTPSecretEncrypted: asBytes(doc["totp_secret_encrypted"]),
		TOTPNonce:       asBytes(doc["totp_nonce"]),
		TOTPEnabled:     asBool(doc["totp_enabled"]),
		EmailVerified:   asBool(doc["email_verified"]),
		AccountStatus:   asString(doc["account_status"]),
		Role:            asString(doc["role"]),
		FailedLoginAttempts: asInt(doc["failed_login_attempts"]),
	}
	user.LockedAt = asTimePtr(doc["locked_at"])
	user.LastLoginAt = asTimePtr(doc["last_login_at"])
	user.LastLoginIPEncrypted = asBytes(doc["last_login_ip_encrypted"])
	user.LastLoginIPNonce = asBytes(doc["last_login_ip_nonce"])
	if v, ok := doc["created_at"].(time.Time); ok {
		user.CreatedAt = v
	}
	if v, ok := doc["updated_at"].(time.Time); ok {
		user.UpdatedAt = v
	}
	return user
}

func decodeProfile(doc bson.M) *goauth.Profile {
	profile := &goauth.Profile{
		UserID:          asString(doc["user_id"]),
		DisplayName:     asString(doc["display_name"]),
		DisplayPhotoURL: asString(doc["display_photo_url"]),
		Bio:             asString(doc["bio"]),
		Locale:          asString(doc["locale"]),
		Timezone:        asString(doc["timezone"]),
	}
	if v, ok := doc["metadata"].(map[string]any); ok {
		profile.Metadata = v
	}
	if v, ok := doc["created_at"].(time.Time); ok {
		profile.CreatedAt = v
	}
	if v, ok := doc["updated_at"].(time.Time); ok {
		profile.UpdatedAt = v
	}
	return profile
}

func decodeVerificationToken(doc bson.M) *goauth.VerificationToken {
	token := &goauth.VerificationToken{
		ID:          asString(doc["_id"]),
		UserID:      asString(doc["user_id"]),
		CodeHash:    asBytes(doc["code_hash"]),
		LinkHash:    asBytes(doc["link_token_hash"]),
		EmailHash:   asBytes(doc["email_hash"]),
		CodeAttempts: asInt(doc["code_attempts"]),
		MaxAttempts: asInt(doc["max_code_attempts"]),
		Used:        asBool(doc["used"]),
	}
	if v, ok := doc["expires_at"].(time.Time); ok {
		token.ExpiresAt = v
	}
	return token
}

func decodePasswordResetToken(doc bson.M) *goauth.PasswordResetToken {
	token := &goauth.PasswordResetToken{
		ID:        asString(doc["_id"]),
		UserID:    asString(doc["user_id"]),
		TokenHash: asBytes(doc["token_hash"]),
		Used:      asBool(doc["used"]),
	}
	if v, ok := doc["expires_at"].(time.Time); ok {
		token.ExpiresAt = v
	}
	return token
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asBytes(v any) []byte {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case []byte:
		return val
	case primitive.Binary:
		return val.Data
	default:
		return nil
	}
}

func asBool(v any) bool {
	if v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func asInt(v any) int {
	switch val := v.(type) {
	case int32:
		return int(val)
	case int64:
		return int(val)
	case int:
		return val
	default:
		return 0
	}
}

func asTimePtr(v any) *time.Time {
	if v == nil {
		return nil
	}
	if t, ok := v.(time.Time); ok {
		return &t
	}
	return nil
}
