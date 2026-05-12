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
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found, using system env")
	}

	database.ConnectDB()

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
		&model.Conversation{},
		&model.Message{},
		&model.SigninHistory{},
	)
	if err != nil {
		log.Fatal("Migration Failed: ", err)
	}

	go services.NotifHub.StartHub()

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			tomorrow := time.Now().AddDate(0, 0, 1).Format("2006-01-02")

			var soonDueTransactions []model.Transaction
			database.DB.Where("status = ? AND DATE(return_date) = ?", "Borrowed", tomorrow).Find(&soonDueTransactions)

			for _, tx := range soonDueTransactions {
				msg := fmt.Sprintf("Reminder: Your borrowed book (ISBN: %s) is due TOMORROW. Please return it on time to avoid penalties.", tx.ISBN)

				notif := model.Notification{
					SchoolID: tx.SchoolID,
					Message:  msg,
					IsRead:   false,
				}
				database.DB.Create(&notif)

				payload := services.NotificationPayload{
					ID:   int64(notif.ID),
					Msg:  msg,
					Time: time.Now().Format("Jan 02, 3:04 PM"),
					Read: false,
				}
				services.NotifHub.SendNotification(tx.SchoolID, payload)
			}
			<-ticker.C
		}
	}()

	app := fiber.New(fiber.Config{
		ReadTimeout:       -1,
		StreamRequestBody: true,
	})

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000",
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))

	routes.Setup(app)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "SmartLib API is running with SSE Support (Fiber)"})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server is starting on port %s...", port)
	log.Fatal(app.Listen(":" + port))
}
