package services

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"fmt"
	"time"
)

// StartDailyPenaltyChecker - Tumatakbo sa background araw-araw
func StartDailyPenaltyChecker() {
	// 1. I-run muna agad pagka-start ng server (para ma-test mo agad ngayon)
	CheckAndApplyPenalties()

	// 2. Mag-set ng timer para tumakbo every 24 hours
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for range ticker.C {
			CheckAndApplyPenalties()
		}
	}()
}

// CheckAndApplyPenalties - Ang mismong logic na naghahanap ng overdue
func CheckAndApplyPenalties() {
	fmt.Println("⏳ [CRON] Running Daily Penalty Checker...")
	today := time.Now().Format("2006-01-02") // Format: YYYY-MM-DD

	var overdueTransactions []model.Transaction

	// Hanapin lahat ng "Borrowed" pa rin pero lagpas na sa araw ngayon
	database.DB.Where("status = ? AND return_date < ?", "Borrowed", today).Find(&overdueTransactions)

	for _, tx := range overdueTransactions {
		// 1. Gawing "Overdue" ang transaction para hindi na siya ma-doble ng check kinabukasan
		database.DB.Model(&tx).Update("status", "Overdue")

		// 2. Hanapin ang Estudyante at dagdagan ng +1 Penalty
		var user model.User
		if err := database.DB.Where("school_id = ?", tx.SchoolID).First(&user).Error; err == nil {
			newPenaltyCount := user.PenaltyCount + 1
			newStatus := user.Status

			// 3. AUTO-LOCK LOGIC: Kapag umabot ng 3, i-lock ang account!
			if newPenaltyCount >= 3 {
				newStatus = "Locked"
				fmt.Printf("🔒 [SYSTEM] Auto-Locked account of %s (3 Strikes Reached)\n", user.SchoolID)
			}

			// 4. I-save pabalik sa database ang bagong penalty count at status
			database.DB.Model(&user).Updates(map[string]interface{}{
				"penalty_count": newPenaltyCount,
				"status":        newStatus,
			})
		}
	}

	fmt.Println("✅ [CRON] Daily Penalty Checker finished.")
}
