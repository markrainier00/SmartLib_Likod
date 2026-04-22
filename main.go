package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/routes"
	"SmartLib_Likod/services"
)

func main() {
	// 1. Load Environment Variables
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found, using system env")
	}

	// 2. Database Connection
	database.ConnectDB()

	// 3. Database Migration
	// Dito natin ilalagay lahat ng models para iwas "Circular Dependency"
	err := database.DB.AutoMigrate(
		&model.User{},
		&model.PasswordReset{},
		&model.Transaction{},
		&model.OTPCode{},
		&model.School{},
		&model.Book{},
		&model.Concern{},
		&model.Wishlist{},
		&model.TransactionHistory{},
		&model.InformationChangeRequest{},
		&model.Notification{},
		&model.Conversation{}, // 🚀 Idinagdag para sa Chat
		&model.Message{},      // 🚀 Idinagdag para sa Chat
	)
	if err != nil {
		log.Fatal("Migration Failed: ", err)
	}

	// ==========================================
	// 4. NOTIFICATION SSE SETUP & CRON SCHEDULER
	// ==========================================

	// Patakbuhin ang Hub sa background (goroutine)
	go services.NotifHub.StartHub()

	// Patakbuhin ang Automatic Due Date Checker
	go services.StartCronJobs()

	// ==========================================

	// 5. Initialize Fiber App
	app := fiber.New(fiber.Config{
		ReadTimeout: -1, // Mahalaga para sa SSE connection
	})

	// 6. Global Middlewares
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000",
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))

	// 7. Setup Routes
	routes.Setup(app)

	// Default Route
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "SmartLib API is running with SSE Support (Fiber)"})
	})

	// 8. Start Server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server is starting on port %s...", port)
	log.Fatal(app.Listen(":" + port))
}
