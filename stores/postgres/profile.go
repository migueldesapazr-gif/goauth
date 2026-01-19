package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"login"
)

// ProfileStore handles profile operations.
type ProfileStore struct {
	pool *pgxpool.Pool
}

func (s *ProfileStore) GetProfile(ctx context.Context, userID string) (*goauth.Profile, error) {
	profile := &goauth.Profile{}
	var metadata []byte
	err := s.pool.QueryRow(ctx, `
		SELECT user_id, display_name, display_photo_url, bio, locale, timezone, metadata, created_at, updated_at
		FROM profiles WHERE user_id = $1
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
	if errors.Is(err, pgx.ErrNoRows) {
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
	_, err := s.pool.Exec(ctx, `
		INSERT INTO profiles (user_id, display_name, display_photo_url, bio, locale, timezone, metadata, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NOW(),NOW())
		ON CONFLICT (user_id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			display_photo_url = EXCLUDED.display_photo_url,
			bio = EXCLUDED.bio,
			locale = EXCLUDED.locale,
			timezone = EXCLUDED.timezone,
			metadata = EXCLUDED.metadata,
			updated_at = NOW()
	`,
		profile.UserID,
		profile.DisplayName,
		profile.DisplayPhotoURL,
		profile.Bio,
		profile.Locale,
		profile.Timezone,
		metadata,
	)
	return err
}

func (s *ProfileStore) DeleteProfile(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM profiles WHERE user_id = $1`, userID)
	return err
}
