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
	"SmartLib_Likod/services" // 🚀 BAGONG DAGDAG: Import para sa background services
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found, using system env")
	}

	database.ConnectDB()

	// 🚀 DITO NATIN IDINAGDAG YUNG BOOK AT CONCERN MODELS
	err := database.DB.AutoMigrate(
		&model.User{},
		&model.PasswordReset{},
		&model.Transaction{},
		&model.Penalty{},
		&model.OTPCode{},
		&model.Book{},    // 👈 Siguraduhin nating may table na rin ang mga Libro
		&model.Concern{}, // 👈 Ito 'yung ginawa natin ngayon para sa Student Concerns!
	)
	if err != nil {
		log.Fatal("Migration Failed: ", err)
	}

	// ==========================================
	// 🚀 BUHAYIN ANG BACKGROUND CHECKER DITO
	// Tumatakbo ito sa background para mag-check ng Overdue at mag-Auto Lock
	// ==========================================
	services.StartDailyPenaltyChecker()

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
