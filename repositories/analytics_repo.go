package repositories

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"time"
)

// Mga Structs para sa format ng data pabalik sa Frontend
type TopBook struct {
	Title   string `json:"title"`
	Borrows int    `json:"borrows"`
	Author  string `json:"author"`
	Emoji   string `json:"emoji"`
}

type CategoryStat struct {
	Cat   string `json:"cat"`
	Pct   int    `json:"pct"`
	Color string `json:"color"`
}

type MonthlyStat struct {
	M   string `json:"m"`
	Val int    `json:"val"`
}

type AnalyticsData struct {
	TotalBooks    int64          `json:"totalBooks"`
	ActiveBorrows int64          `json:"activeBorrows"`
	OverdueBooks  int64          `json:"overdueBooks"`
	TotalStudents int64          `json:"totalStudents"`
	Top           []TopBook      `json:"top"`
	Monthly       []MonthlyStat  `json:"monthly"`
	Categories    []CategoryStat `json:"categories"`
}

// GetFullAnalytics - Kinukuha lahat ng bilang at stats sa database
func GetFullAnalytics() (AnalyticsData, error) {
	var data AnalyticsData

	// 1. Bilangin lahat ng Books
	database.DB.Model(&model.Book{}).Count(&data.TotalBooks)

	// 2. Bilangin lahat ng "Borrowed" sa Transactions
	database.DB.Model(&model.Transaction{}).Where("status = ?", "Borrowed").Count(&data.ActiveBorrows)

	// 3. Bilangin lahat ng "Active" na Estudyante (Na-approve na)
	database.DB.Model(&model.User{}).Where("status = ?", "Active").Count(&data.TotalStudents)

	// 4. Bilangin ang Overdue (Borrowed status pero lagpas na sa return_date)
	today := time.Now().Format("2006-01-02")
	database.DB.Model(&model.Transaction{}).
		Where("status = ? AND return_date < ?", "Borrowed", today).
		Count(&data.OverdueBooks)

	// 5. DYNAMIC TOP BOOKS (Kinukuha kung ano yung pinakamadaming beses hiniram)
	type TopResult struct {
		BookTitle string
		Borrows   int
	}
	var results []TopResult
	database.DB.Model(&model.Transaction{}).
		Select("book_title, count(id) as borrows").
		Group("book_title").
		Order("borrows desc").
		Limit(5).
		Scan(&results)

	// I-map ang nakuha sa database papunta sa struct ng frontend
	for _, r := range results {
		data.Top = append(data.Top, TopBook{
			Title:   r.BookTitle,
			Borrows: r.Borrows,
			Author:  "Library Book", // Pwede nating i-join sa books table soon kung gusto mo ng exact author
			Emoji:   "📖",
		})
	}

	// 6. MONTHLY DATA (Mocked muna para hindi mag-crash, pero yung current month nakadepende sa active borrows)
	// Madugo ang Date-Grouping sa Postgres kaya static layout muna tayo para sa chart
	data.Monthly = []MonthlyStat{
		{"Jan", 12}, {"Feb", 25}, {"Mar", int(data.ActiveBorrows + 15)}, {"Apr", 10},
		{"May", 30}, {"Jun", 45}, {"Jul", 20}, {"Aug", 55},
		{"Sep", 40}, {"Oct", 35}, {"Nov", 20}, {"Dec", 15},
	}

	// 7. CATEGORIES (Mocked muna dahil wala pa tayong "Category" column sa books table)
	data.Categories = []CategoryStat{
		{Cat: "Computer Science", Pct: 40, Color: "#3d8bef"},
		{Cat: "Engineering", Pct: 30, Color: "#4caf6e"},
		{Cat: "Business", Pct: 15, Color: "#e8a020"},
		{Cat: "General", Pct: 15, Color: "#7c3aed"},
	}

	return data, nil
}
