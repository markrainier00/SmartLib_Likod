package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"

	"SmartLib_Likod/database"
	"SmartLib_Likod/middleware"
	"SmartLib_Likod/model"
	"SmartLib_Likod/routes"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found, using system env")
	}

	database.ConnectDB()

	err := database.DB.AutoMigrate(
		&model.User{},
		&model.PasswordReset{},
		&model.Transaction{},
		&model.Penalty{},
		&model.OTPCode{},
		&model.School{},
		&model.Book{},
		&model.Concern{},
		&model.Wishlist{},
	)
	if err != nil {
		log.Fatal("Migration Failed: ", err)
	}

	app := fiber.New()

	middleware.SetupCORS(app)

	routes.Setup(app)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "SmartLib API is running"})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(app.Listen(":" + port))
}
