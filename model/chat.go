package model

import (
	"gorm.io/gorm"
)

// ==========================================
// 🚀 CONVERSATION TABLE
// Ito yung "Chat Room" sa pagitan ng Student at Admin
// ==========================================
type Conversation struct {
	gorm.Model
	StudentID string `json:"student_id" gorm:"index"`      // Sino ang estudyanteng nag-chat?
	AdminID   string `json:"admin_id"`                     // Sinong admin ang sumagot? (Pwedeng blangko muna)
	Subject   string `json:"subject"`                      // Tungkol saan ang chat? (e.g., "Missing Book", "Overdue Penalty")
	Status    string `json:"status" gorm:"default:'Open'"` // Open, Resolved, o Closed

	// Relasyon: Ang isang Conversation ay maraming Messages
	Messages []Message `json:"messages" gorm:"foreignKey:ConversationID"`
}

// ==========================================
// 🚀 MESSAGE TABLE
// Ito yung mismong mga chat bubbles (texts)
// ==========================================
type Message struct {
	gorm.Model
	ConversationID uint   `json:"conversation_id" gorm:"index"` // Saang chat room ito kabilang?
	SenderID       string `json:"sender_id"`                    // Sino ang nag-send? (School ID ng student o Admin ID)
	SenderRole     string `json:"sender_role"`                  // 'student' ba o 'admin'? Para alam ng React kung blue o gray ang bubble
	Content        string `json:"content"`                      // Ang mismong message!
	IsRead         bool   `json:"is_read" gorm:"default:false"` // Nabasa na ba?
}
