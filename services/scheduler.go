package services

import (
	"fmt"
	"log"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"

	"github.com/robfig/cron/v3"
)

func StartCronJobs() {
	// 1. I-set sa Oras ng Pilipinas (Manila Time)
	manilaTime, err := time.LoadLocation("Asia/Manila")
	if err != nil {
		log.Println("Error loading timezone, using local time")
		manilaTime = time.Local
	}

	c := cron.New(cron.WithLocation(manilaTime))

	// 2. I-set ang Schedule (Araw-araw tuwing 8:00 AM)
	// 💡 TIP: Para ma-test mo ngayon agad nang hindi naghihintay ng 8:00 AM,
	// palitan mo pansamantala ang "0 8 * * *" ng "@every 1m" (tutunog every minute!)
	c.AddFunc("0 8 * * *", func() {
		log.Println("⏰ Checking for due dates...")
		checkDueDates()
	})

	c.Start()
	log.Println("🤖 Automatic Scheduler (Cron) Started!")
}

func checkDueDates() {
	var activeBorrows []model.Transaction

	// Kunin lahat ng librong kasalukuyang hinihiram (Borrowed status)
	if err := database.DB.Where("status = ?", "Borrowed").Find(&activeBorrows).Error; err != nil {
		log.Println("Cron Error: Failed to fetch active borrows", err)
		return
	}

	now := time.Now()
	for _, borrow := range activeBorrows {
		// Kunin ang diperensya ng oras at araw (Return Date minus Ngayon)
		hoursLeft := borrow.ReturnDate.Sub(now).Hours()
		daysLeft := int(hoursLeft / 24)

		// 🔔 Kung bukas na ang deadline (1 araw na lang o less than 24 hours)
		if daysLeft == 1 || (hoursLeft > 0 && hoursLeft <= 24) {
			msg := fmt.Sprintf("⏰ REMINDER: Your borrowed book (ISBN: %s) is due TOMORROW. Please return it on time.", borrow.ISBN)
			SendSystemNotification(borrow.SchoolID, msg)

			// 🚨 Kung lagpas na sa due date (Overdue)
		} else if hoursLeft < 0 {
			msg := fmt.Sprintf("🚨 OVERDUE: Your borrowed book (ISBN: %s) is past its due date. Please return it immediately.", borrow.ISBN)
			SendSystemNotification(borrow.SchoolID, msg)
		}
	}
}

// Function na ipapadala ang live notification sa database at sa React
func SendSystemNotification(schoolID string, message string) {
	notif := &model.Notification{
		SchoolID: schoolID,
		Message:  message,
		IsRead:   false,
	}
	database.DB.Create(notif)

	payload := NotificationPayload{
		ID:   int64(notif.ID),
		Msg:  message,
		Time: time.Now().Format("Jan 02, 3:04 PM"),
		Read: false,
	}
	NotifHub.SendNotification(schoolID, payload)
}
