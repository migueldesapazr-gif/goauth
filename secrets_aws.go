package goauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// AWSSSMConfig holds AWS SSM Parameter Store configuration.
type AWSSSMConfig struct {
	JWTParameter        string
	EncryptionParameter string
	PepperParameter     string
	Region              string
}

// SecretsFromAWSSecretsManager loads secrets from AWS Secrets Manager.
// The secret value must be a JSON object with jwt/encryption/pepper keys.
func SecretsFromAWSSecretsManager(ctx context.Context, cfg AWSSecretsConfig) (Secrets, error) {
	if cfg.SecretName == "" {
		return Secrets{}, errors.New("aws secret name is required")
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return Secrets{}, err
	}
	client := secretsmanager.NewFromConfig(awsCfg)
	resp, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(cfg.SecretName),
	})
	if err != nil {
		return Secrets{}, err
	}
	var payload []byte
	switch {
	case resp.SecretString != nil:
		payload = []byte(*resp.SecretString)
	case resp.SecretBinary != nil:
		payload = resp.SecretBinary
	default:
		return Secrets{}, errors.New("aws secret value is empty")
	}
	return SecretsFromJSON(payload, cfg.Keys)
}

// SecretsFromAWSSSM loads secrets from AWS SSM Parameter Store.
func SecretsFromAWSSSM(ctx context.Context, cfg AWSSSMConfig) (Secrets, error) {
	if cfg.JWTParameter == "" || cfg.EncryptionParameter == "" || cfg.PepperParameter == "" {
		return Secrets{}, errors.New("ssm parameters are required")
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return Secrets{}, err
	}
	client := ssm.NewFromConfig(awsCfg)
	resp, err := client.GetParameters(ctx, &ssm.GetParametersInput{
		Names:          []string{cfg.JWTParameter, cfg.EncryptionParameter, cfg.PepperParameter},
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return Secrets{}, err
	}
	values := map[string]string{}
	for _, param := range resp.Parameters {
		if param.Name == nil || param.Value == nil {
			continue
		}
		values[*param.Name] = *param.Value
	}
	jwt, err := decodeSecret(values[cfg.JWTParameter])
	if err != nil {
		return Secrets{}, fmt.Errorf("jwt parameter: %w", err)
	}
	enc, err := decodeSecret(values[cfg.EncryptionParameter])
	if err != nil {
		return Secrets{}, fmt.Errorf("encryption parameter: %w", err)
	}
	pepper, err := decodeSecret(values[cfg.PepperParameter])
	if err != nil {
		return Secrets{}, fmt.Errorf("pepper parameter: %w", err)
	}
	return Secrets{
		JWTSecret:     jwt,
		EncryptionKey: enc,
		Pepper:        pepper,
	}, nil
}

// WithSecretsFromAWSSecretsManager loads secrets from AWS Secrets Manager.
func WithSecretsFromAWSSecretsManager(ctx context.Context, cfg AWSSecretsConfig) Option {
	return func(s *AuthService) error {
		secrets, err := SecretsFromAWSSecretsManager(ctx, cfg)
		if err != nil {
			return err
		}
		return WithSecrets(secrets)(s)
	}
}

// WithSecretsFromAWSSSM loads secrets from AWS SSM Parameter Store.
func WithSecretsFromAWSSSM(ctx context.Context, cfg AWSSSMConfig) Option {
	return func(s *AuthService) error {
		secrets, err := SecretsFromAWSSSM(ctx, cfg)
		if err != nil {
			return err
		}
		return WithSecrets(secrets)(s)
	}
}
