package main

import (
	"errors"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type tokenModel struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID       primitive.ObjectID `bson:"userId,omitempty" json:"userId"`
	AccessToken  string             `bson:"accessToken,omitempty" json:"accessToken"`
	RefreshToken string             `bson:"refreshToken,omitempty" json:"refreshToken"`
}

func (t *tokenModel) generate(userID primitive.ObjectID) error {
	if err := t.generateAccessToken(userID); err != nil {
		return err
	}

	if err := t.generateRefreshToken(); err != nil {
		return err
	}

	return nil
}

func (t *tokenModel) generateAccessToken(userID primitive.ObjectID) error {
	accessClaims := jwt.MapClaims{
		"exp":    time.Now().Add(15 * time.Minute).Unix(),
		"userId": userID.Hex(),
	}
	accessToken, err := generateJwtToken(accessClaims, os.Getenv("ACCESS_TOKEN_SECRET"))
	if err != nil {
		return err
	}

	t.AccessToken = accessToken

	return nil
}

func (t *tokenModel) generateRefreshToken() error {
	refreshClaims := jwt.MapClaims{
		"exp": time.Now().Add(24 * time.Hour * 7).Unix(),
	}
	refreshToken, err := generateJwtToken(refreshClaims, os.Getenv("REFRESH_TOKEN_SECRET"))
	if err != nil {
		return err
	}

	t.RefreshToken = refreshToken

	return nil
}

func generateJwtToken(claims jwt.MapClaims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenValue, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenValue, nil
}

func decodeAccessToken(token string) (*jwt.Token, error) {
	decoded, err := decode(token, os.Getenv("ACCESS_TOKEN_SECRET"))
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func decodeRefreshToken(token string) (*jwt.Token, error) {
	decoded, err := decode(token, os.Getenv("REFRESH_TOKEN_SECRET"))
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func decode(token, secret string) (*jwt.Token, error) {
	decoded, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		if err.Error() == "Token is expired" {
			return nil, nil
		}

		return nil, err
	}

	return decoded, nil
}
