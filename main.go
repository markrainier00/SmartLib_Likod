package main

import (
	"fmt"
	"log"
	"os"
	"time"

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

	// 🚀 DUE DATE CHECKER (Tumatakbo sa background)
	go func() {
		// Magche-check ito araw-araw (Every 24 hours)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			// Kukunin ang petsa bukas
			tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

			var soonDueTransactions []model.Transaction
			// Hanapin lahat ng "Borrowed" na ang ReturnDate ay tugma bukas
			database.DB.Where("status = ? AND DATE(return_date) = ?", "Borrowed", tomorrow).Find(&soonDueTransactions)

			for _, tx := range soonDueTransactions {
				msg := fmt.Sprintf("Reminder: Your borrowed book (ISBN: %s) is due TOMORROW. Please return it on time to avoid penalties.", tx.ISBN)

				// 1. I-save ang notification sa database
				notif := model.Notification{
					SchoolID: tx.SchoolID,
					Message:  msg,
					IsRead:   false,
				}
				database.DB.Create(&notif)

				// 2. I-send din nang live kung naka-online ang student!
				payload := services.NotificationPayload{
					ID:   int64(notif.ID),
					Msg:  msg,
					Time: time.Now().Format("Jan 02, 3:04 PM"),
					Read: false,
				}
				services.NotifHub.SendNotification(tx.SchoolID, payload)
			}
			<-ticker.C // Maghihintay ng 24 hours bago umikot ulit
		}
	}()

	// ==========================================

	// 5. Initialize Fiber App
	app := fiber.New(fiber.Config{
		ReadTimeout: -1, // Mahalaga para sa SSE connection
	})

	// 6. Global Middlewares
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000, http://192.168.8.198:8080",
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
