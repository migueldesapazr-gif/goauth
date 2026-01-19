package goauth

import (
	"errors"
	"net/http"
	"time"
)

const (
	maxProfileDisplayName = 100
	maxProfilePhotoURL    = 2048
	maxProfileBio         = 500
	maxProfileLocale      = 32
	maxProfileTimezone    = 64
)

type profileUpdateRequest struct {
	DisplayName     string         `json:"display_name,omitempty"`
	DisplayPhotoURL string         `json:"display_photo_url,omitempty"`
	Bio             string         `json:"bio,omitempty"`
	Locale          string         `json:"locale,omitempty"`
	Timezone        string         `json:"timezone,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

func (s *AuthService) handleProfileGet(w http.ResponseWriter, r *http.Request) {
	if s.profileStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "profile store not enabled")
		return
	}
	user, ok := GetUserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
		return
	}
	profile, err := s.profileStore.GetProfile(r.Context(), user.ID)
	if err != nil {
		if errors.Is(err, ErrProfileNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{"profile": nil})
			return
		}
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profile": profile})
}

func (s *AuthService) handleProfileUpdate(w http.ResponseWriter, r *http.Request) {
	if s.profileStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "profile store not enabled")
		return
	}
	user, ok := GetUserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
		return
	}
	var req profileUpdateRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	if err := validateProfileInput(req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}
	profile := Profile{
		UserID:          user.ID,
		DisplayName:     req.DisplayName,
		DisplayPhotoURL: req.DisplayPhotoURL,
		Bio:             req.Bio,
		Locale:          req.Locale,
		Timezone:        req.Timezone,
		Metadata:        req.Metadata,
		UpdatedAt:       time.Now(),
	}
	if err := s.profileStore.UpsertProfile(r.Context(), profile); err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profile": profile})
}

func validateProfileInput(req profileUpdateRequest) error {
	if len(req.DisplayName) > maxProfileDisplayName {
		return errors.New("display_name too long")
	}
	if len(req.DisplayPhotoURL) > maxProfilePhotoURL {
		return errors.New("display_photo_url too long")
	}
	if len(req.Bio) > maxProfileBio {
		return errors.New("bio too long")
	}
	if len(req.Locale) > maxProfileLocale {
		return errors.New("locale too long")
	}
	if len(req.Timezone) > maxProfileTimezone {
		return errors.New("timezone too long")
	}
	return nil
}
