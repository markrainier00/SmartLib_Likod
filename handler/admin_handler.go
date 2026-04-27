package handler

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
)

func RegisterStaffHandler(c *fiber.Ctx) error {
	var input services.RegisterStaffInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.FirstName == "" || input.LastName == "" || input.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.RegisterStaffService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response.ResponseModel{
		RetCode: "201",
		Message: "Staff registration successful.",
		Data:    nil,
	})
}

func GetRegistrationHistoryHandler(c *fiber.Ctx) error {
	history, err := services.GetRegistrationHistoryService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   status.RetCode500,
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Registration history retrieved",
		Data:    history,
	})
}

func CreateProgramHandler(c *fiber.Ctx) error {
	var input services.SchoolInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid input."})
	}
	if input.Department == "" || input.Program == "" || input.Duration == 0 {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "All fields are required."})
	}

	school, err := services.CreateSchoolService(input)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to create program."})
	}

	return c.Status(201).JSON(response.ResponseModel{
		RetCode: "201",
		Message: "Program created successfully.",
		Data:    school,
	})
}

func UpdateProgramHandler(c *fiber.Ctx) error {
	id, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid ID."})
	}

	var input services.SchoolInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid input."})
	}
	if input.Department == "" || input.Program == "" || input.Duration == 0 {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "All fields are required."})
	}

	if err := services.UpdateSchoolService(uint(id), input); err != nil {
		return c.Status(404).JSON(fiber.Map{"isSuccess": false, "message": err.Error()})
	}

	return c.Status(200).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Program updated successfully.",
	})
}

func DeleteProgramHandler(c *fiber.Ctx) error {
	id, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid ID."})
	}

	if err := services.DeleteSchoolService(uint(id)); err != nil {
		return c.Status(404).JSON(fiber.Map{"isSuccess": false, "message": err.Error()})
	}

	return c.Status(200).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Program deleted successfully.",
	})
}

func GetSchool(c *fiber.Ctx) error {
	school, err := services.GetSchoolService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    school,
	})
}

func GetWholeUsers(c *fiber.Ctx) error {
	users, err := services.GetWholeUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetAllUsers(c *fiber.Ctx) error {
	users, err := services.GetAllUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetPendingUsers(c *fiber.Ctx) error {
	users, err := services.GetPendingUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetArchivedStudents(c *fiber.Ctx) error {
	users, err := services.GetArchivedStudentsService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetArchivedUsers(c *fiber.Ctx) error {
	users, err := services.GetArchivedUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func ApproveUser(c *fiber.Ctx) error {
	var input services.ApproveRejectInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Invalid request body",
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "School ID is required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.ApproveUserService(input.SchoolID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "User approved successfully",
		Data:    nil,
	})
}

func RejectUser(c *fiber.Ctx) error {
	var input services.ApproveRejectInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Invalid request body",
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "School ID is required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if input.Reason == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Rejection reason is required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.RejectUserService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "User rejected successfully",
		Data:    nil,
	})
}

func GetStudentUsers(c *fiber.Ctx) error {
	users, err := services.GetStudentUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetSpecificUser(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	users, err := services.GetSpecificUserService(schoolID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func UpdateUserStatus(c *fiber.Ctx) error {
	var input services.UpdateUserStatusInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Invalid request body",
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" || input.Status == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "School ID and status are required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.UpdateUserStatusService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "User status updated successfully",
		Data:    nil,
	})
}

func ApproveInformationRequestHandler(c *fiber.Ctx) error {
	var input struct {
		ID uint `json:"id"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input",
		})
	}

	if input.ID == 0 {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "ID is required",
		})
	}

	if err := services.ApproveInformationRequest(input.ID); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Request approved successfully",
	})
}

func RejectInformationRequestHandler(c *fiber.Ctx) error {
	var input struct {
		ID           uint   `json:"id"`
		RejectReason string `json:"reject_reason"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input",
		})
	}

	if input.ID == 0 {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "ID is required",
		})
	}

	if input.RejectReason == "" {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Reject reason is required",
		})
	}

	if err := services.RejectInformationRequest(input.ID, input.RejectReason); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Request rejected successfully",
	})
}

func GetAllAccounts(c *fiber.Ctx) error {
	users, err := services.GetAllAccountsService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetInformationChange(c *fiber.Ctx) error {
	users, err := services.GetInformationChangeService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

type MonthlyData struct {
	M   string `json:"m"`
	Val int    `json:"val"`
}

type CategoryData struct {
	Cat   string `json:"cat"`
	Pct   int    `json:"pct"`
	Color string `json:"color"`
}

type TopBookData struct {
	Title   string `json:"title"`
	Author  string `json:"author"`
	Borrows int    `json:"borrows"`
	Emoji   string `json:"emoji"`
}

func GetAnalyticsFullHandler(c *fiber.Ctx) error {
	fromStr := c.Query("from", "")
	toStr := c.Query("to", "")
	view := c.Query("view", "monthly")

	now := time.Now()
	from := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.Local)
	to := time.Date(now.Year(), 12, 31, 23, 59, 59, 0, time.Local)

	if fromStr != "" {
		if parsed, err := time.Parse("2006-01-02", fromStr); err == nil {
			from = parsed
		}
	}
	if toStr != "" {
		if parsed, err := time.Parse("2006-01-02", toStr); err == nil {
			to = parsed.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		}
	}

	var totalBooks int64
	database.DB.Model(&model.Book{}).
		Select("COALESCE(SUM(CAST(copies AS INTEGER)), 0)").
		Scan(&totalBooks)

	var totalReserved int64
	var totalAvailable int64
	database.DB.Model(&model.Book{}).
		Select("COALESCE(SUM(reserved), 0)").
		Scan(&totalReserved)
	database.DB.Model(&model.Book{}).
		Select("COALESCE(SUM(available), 0)").
		Scan(&totalAvailable)
	activeBorrows := totalBooks - (totalReserved + totalAvailable)

	var totalStudents int64
	database.DB.Model(&model.User{}).
		Where("LOWER(role) = ? AND LOWER(status) = ?", "student", "active").
		Count(&totalStudents)

	// ==========================================
	// Monthly Data — respects view mode + date range
	// ==========================================
	type MonthlyRaw struct {
		Label string
		Total int
	}

	var rawResults []MonthlyRaw
	var monthly []MonthlyData

	switch view {
	case "daily":
		database.DB.Model(&model.Transaction{}).
			Select("TO_CHAR(created_at, 'YYYY-MM-DD') as label, count(*) as total").
			Where("created_at BETWEEN ? AND ?", from, to).
			Group("label").
			Order("label asc").
			Scan(&rawResults)

		// Fill all days in range
		dayMap := make(map[string]int)
		for _, r := range rawResults {
			dayMap[r.Label] = r.Total
		}
		cursor := from
		for !cursor.After(to) {
			key := cursor.Format("2006-01-02")
			monthly = append(monthly, MonthlyData{M: key, Val: dayMap[key]})
			cursor = cursor.AddDate(0, 0, 1)
		}

	case "yearly":
		database.DB.Model(&model.Transaction{}).
			Select("TO_CHAR(created_at, 'YYYY') as label, count(*) as total").
			Where("created_at BETWEEN ? AND ?", from, to).
			Group("label").
			Order("label asc").
			Scan(&rawResults)

		yearMap := make(map[string]int)
		for _, r := range rawResults {
			yearMap[r.Label] = r.Total
		}
		for y := from.Year(); y <= to.Year(); y++ {
			key := fmt.Sprintf("%d", y)
			monthly = append(monthly, MonthlyData{M: key, Val: yearMap[key]})
		}

	default: // monthly
		database.DB.Model(&model.Transaction{}).
			Select("TO_CHAR(created_at, 'Mon') as label, count(*) as total").
			Where("created_at BETWEEN ? AND ?", from, to).
			Group("label").
			Order("MIN(created_at) asc").
			Scan(&rawResults)

		allMonths := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
		monthMap := make(map[string]int)
		for _, r := range rawResults {
			monthMap[r.Label] = r.Total
		}
		for _, m := range allMonths {
			monthly = append(monthly, MonthlyData{M: m, Val: monthMap[m]})
		}
	}

	// ==========================================
	// Categories — filtered by date range
	// ==========================================
	var catCounts []struct {
		Category string
		Count    int
	}

	database.DB.Raw(`
        SELECT
            CASE
                WHEN TRIM(cat) = '' OR TRIM(cat) IS NULL THEN 'Uncategorized'
                ELSE TRIM(cat)
            END AS category,
            COUNT(*) AS count
        FROM transaction_histories t
        JOIN books b ON b.isbn = t.isbn,
            UNNEST(STRING_TO_ARRAY(COALESCE(NULLIF(TRIM(b.category), ''), 'Uncategorized'), ',')) AS cat
        WHERE t.event IN ('Borrow', 'Return')
          AND t.date BETWEEN ? AND ?
        GROUP BY
            CASE
                WHEN TRIM(cat) = '' OR TRIM(cat) IS NULL THEN 'Uncategorized'
                ELSE TRIM(cat)
            END
        ORDER BY count DESC
    `, from, to).Scan(&catCounts)

	totalCatCount := 0
	for _, cat := range catCounts {
		totalCatCount += cat.Count
	}

	colors := []string{"#3d8bef", "#7c3aed", "#4caf6e", "#f59e0b", "#ec4899", "#06b6d4", "#f97316"}
	var categories []CategoryData

	if len(catCounts) > 0 {
		for i, cat := range catCounts {
			pct := 0
			if totalCatCount > 0 {
				pct = int((float64(cat.Count) / float64(totalCatCount)) * 100)
			}
			catName := strings.TrimSpace(cat.Category)
			if catName == "" {
				catName = "Uncategorized"
			}
			categories = append(categories, CategoryData{
				Cat:   catName,
				Pct:   pct,
				Color: colors[i%len(colors)],
			})
		}
	} else {
		categories = []CategoryData{
			{Cat: "General", Pct: 0, Color: "#3d8bef"},
		}
	}

	// ==========================================
	// Top Borrowed Books — filtered by date range
	// ==========================================
	var topBorrows []struct {
		ISBN  string
		Count int
	}

	database.DB.Model(&model.Transaction{}).
		Select("isbn, count(*) as count").
		Where("created_at BETWEEN ? AND ?", from, to).
		Group("isbn").
		Order("count desc").
		Limit(5).
		Scan(&topBorrows)

	var top []TopBookData
	for _, tb := range topBorrows {
		var book model.Book
		database.DB.Where("isbn = ?", tb.ISBN).First(&book)
		title := book.Title
		if title == "" {
			title = "Unknown Book (ISBN: " + tb.ISBN + ")"
		}
		top = append(top, TopBookData{
			Title:   title,
			Author:  book.Author,
			Borrows: tb.Count,
			Emoji:   "📖",
		})
	}

	if len(top) == 0 {
		top = []TopBookData{}
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data": fiber.Map{
			"totalBooks":    totalBooks,
			"activeBorrows": activeBorrows,
			"totalStudents": totalStudents,
			"monthly":       monthly,
			"categories":    categories,
			"top":           top,
		},
	})
}
