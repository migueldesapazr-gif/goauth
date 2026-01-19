// Package sqlstore provides a SQL store implementation for goauth using database/sql.
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"login"
)

// ProfileStore handles profile operations.
type ProfileStore struct {
	db *sql.DB
}

func (s *ProfileStore) GetProfile(ctx context.Context, userID string) (*goauth.Profile, error) {
	profile := &goauth.Profile{}
	var metadata []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT user_id, display_name, display_photo_url, bio, locale, timezone, metadata, created_at, updated_at
		FROM profiles WHERE user_id = ?
	`, userID).Scan(
		&profile.UserID,
		&profile.DisplayName,
		&profile.DisplayPhotoURL,
		&profile.Bio,
		&profile.Locale,
		&profile.Timezone,
		&metadata,
		&profile.CreatedAt,
		&profile.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, goauth.ErrProfileNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &profile.Metadata)
	}
	return profile, nil
}

func (s *ProfileStore) UpsertProfile(ctx context.Context, profile goauth.Profile) error {
	var metadata any
	if profile.Metadata != nil {
		payload, err := json.Marshal(profile.Metadata)
		if err != nil {
			return err
		}
		metadata = payload
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE profiles
		SET display_name = ?, display_photo_url = ?, bio = ?, locale = ?, timezone = ?, metadata = ?, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ?
	`, profile.DisplayName, profile.DisplayPhotoURL, profile.Bio, profile.Locale, profile.Timezone, metadata, profile.UserID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO profiles (user_id, display_name, display_photo_url, bio, locale, timezone, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, profile.UserID, profile.DisplayName, profile.DisplayPhotoURL, profile.Bio, profile.Locale, profile.Timezone, metadata)
	return err
}

func (s *ProfileStore) DeleteProfile(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM profiles WHERE user_id = ?`, userID)
	return err
}
