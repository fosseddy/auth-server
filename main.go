package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/joho/godotenv"
)

var database *mongo.Database

func main() {
	godotenv.Load(".env")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Conntecting to MongoDB...")
	client, err := mongo.Connect(
		ctx,
		options.Client().ApplyURI(os.Getenv("MONGO_URI")),
	)

	if err != nil {
		panic(err)
	}

	database = client.Database("tm-auth")
	fmt.Println("MongoDB connected")

	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	e := echo.New()
	e.Use(middleware.Logger())

	e.POST("/api/auth/register", register)
	e.POST("/api/auth/login", login)
	e.POST("/api/auth/logout", logout)
	e.POST("/api/auth/refresh-access-token", refreshAccessToken)
	e.POST("/api/auth/clear-expired-tokens", clearExpiredTokens)

	e.Logger.Fatal(e.Start(":8080"))
}

func register(c echo.Context) error {
	customHeader := c.Request().Header.Get(os.Getenv("CUSTOM_ACCESS_HEADER"))
	if customHeader != os.Getenv("CUSTOM_ACCESS_HEADER_VALUE") {
		return c.JSON(http.StatusForbidden, map[string]string{
			"status":  "error",
			"message": "You are not allowed to use this resource",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	newUser := new(userModel)
	if err := c.Bind(newUser); err != nil {
		return err
	}

	// Validate body
	if len(newUser.Username) == 0 || len(newUser.Password) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "username or password is empty",
		})
	}

	// Validate if user already exist
	existingUser := new(userModel)
	uc := database.Collection("users")
	singleRes := uc.FindOne(
		ctx,
		bson.D{{Key: "username", Value: newUser.Username}},
	)

	if err := singleRes.Decode(existingUser); err != nil {
		if err == mongo.ErrNoDocuments {
			existingUser = nil
		} else {
			return err
		}
	}

	if existingUser != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "User already exist",
		})
	}

	// Hash password
	if err := newUser.hashPassword(); err != nil {
		return err
	}

	// Add user to database
	if _, err := uc.InsertOne(ctx, newUser); err != nil {
		return err
	}

	return c.JSON(http.StatusCreated, map[string]string{
		"status":   "success",
		"messages": "User successfully registered",
	})
}

func login(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	body := new(userModel)
	if err := c.Bind(body); err != nil {
		return err
	}

	// Validate body
	if len(body.Username) == 0 || len(body.Password) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "username or password is empty",
		})
	}

	// Check if user exist
	user := new(userModel)
	uc := database.Collection("users")
	singleRes := uc.FindOne(
		ctx,
		bson.D{{Key: "username", Value: body.Username}},
	)

	if err := singleRes.Decode(user); err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"status":  "error",
				"message": "Wrong credentials",
			})
		}

		return err
	}

	// Compare passwords
	if err := user.comparePasswords(body.Password); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "Wrong credentials",
		})
	}

	// Generate JWT access, refresh token pair
	token := new(tokenModel)
	token.UserID = user.ID

	if err := token.generate(user.ID); err != nil {
		return err
	}

	// Add tokens to database
	tc := database.Collection("tokens")
	if _, err := tc.InsertOne(ctx, token); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":   "success",
		"messages": "User successfully logged in",
		"data": map[string]interface{}{
			"accessToken":  token.AccessToken,
			"refreshToken": token.RefreshToken,
			"user": map[string]interface{}{
				"id":       user.ID.Hex(),
				"username": user.Username,
			},
		},
	})
}

func logout(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Validate header
	header := c.Request().Header.Get("Authorization")
	if header == "" {
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"status":  "error",
			"message": "Not authorized",
		})
	}

	pair := strings.Split(header, " ")
	if len(pair) != 2 {
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"status":  "error",
			"message": "Not authorized",
		})
	}

	tokenString := pair[1]

	// Validate token
	decoded, err := decodeAccessToken(tokenString)
	if err != nil {
		return err
	}

	if decoded != nil {
		tc := database.Collection("tokens")
		_, err = tc.DeleteOne(ctx, bson.D{{Key: "accessToken", Value: decoded.Raw}})
		if err != nil {
			return err
		}
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status":  "success",
		"message": "User successfully logged out",
	})
}

func refreshAccessToken(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var body = new(struct {
		RefreshToken string `json:"refreshToken"`
	})

	err := c.Bind(body)
	if err != nil {
		return err
	}

	// Validate body
	if len(body.RefreshToken) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "Refresh token is empty",
		})
	}

	// Decode and validate token
	decoded, err := decodeRefreshToken(body.RefreshToken)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "Invalid refresh token",
		})
	}

	if decoded == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"status":  "error",
			"message": "Refresh token has expired",
		})
	}

	// Delete pair from database
	prevToken := new(tokenModel)
	tc := database.Collection("tokens")
	result := tc.FindOneAndDelete(
		ctx,
		bson.D{{Key: "refreshToken", Value: decoded.Raw}},
	)
	if err := result.Decode(prevToken); err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"status":  "error",
				"message": "Refresh token does not exist",
			})
		}

		return err
	}

	// Generate new pair of tokens
	newToken := new(tokenModel)
	newToken.UserID = prevToken.UserID

	if err := newToken.generate(prevToken.UserID); err != nil {
		return err
	}

	// Add new pair of tokens to database
	if _, err := tc.InsertOne(ctx, newToken); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "access token was refreshed",
		"data": map[string]interface{}{
			"accessToken":  newToken.AccessToken,
			"refreshToken": newToken.RefreshToken,
		},
	})
}

func clearExpiredTokens(c echo.Context) error {
	customHeader := c.Request().Header.Get(os.Getenv("CUSTOM_ACCESS_HEADER"))
	if customHeader != os.Getenv("CUSTOM_ACCESS_HEADER_VALUE") {
		return c.JSON(http.StatusForbidden, map[string]string{
			"status":  "error",
			"message": "You are not allowed to use this resource",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tc := database.Collection("tokens")
	cur, err := tc.Find(ctx, bson.D{})
	if err != nil {
		return err
	}

	defer cur.Close(ctx)

	var tokensToDelete []primitive.ObjectID
	for cur.Next(ctx) {
		token := new(tokenModel)
		if err = cur.Decode(token); err != nil {
			return err
		}

		decoded, err := decodeRefreshToken(token.RefreshToken)
		if err != nil {
			return err
		}

		if decoded == nil {
			tokensToDelete = append(tokensToDelete, token.ID)
		}
	}

	if len(tokensToDelete) == 0 {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":   "success",
			"messages": "nothing to delete",
			"data": map[string]int{
				"count": 0,
			},
		})
	}

	deleteRes, err := tc.DeleteMany(ctx, bson.D{
		{Key: "_id", Value: bson.D{{Key: "$in", Value: tokensToDelete}}},
	})
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Expired tokens were successfully deleted",
		"data": map[string]interface{}{
			"count": deleteRes.DeletedCount,
		},
	})
}
