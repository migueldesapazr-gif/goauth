package goauth

import (
	"context"
	"errors"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// LastLoginIP returns the last stored login IP for a user when IP storage is enabled.
func (s *AuthService) LastLoginIP(ctx context.Context, userID string) (string, error) {
	if !s.config.IPPrivacy.StoreIP {
		return "", errors.New("ip storage disabled")
	}
	user, err := s.store.Users().GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if len(user.LastLoginIPEncrypted) == 0 {
		return "", nil
	}
	if !s.config.IPPrivacy.EncryptIP {
		return string(user.LastLoginIPEncrypted), nil
	}
	if s.keys == nil {
		return "", errors.New("encryption keys not available")
	}
	ip, err := crypto.Decrypt(user.LastLoginIPEncrypted, user.LastLoginIPNonce, s.keys.IPKey)
	if err != nil {
		return "", err
	}
	return string(ip), nil
}
