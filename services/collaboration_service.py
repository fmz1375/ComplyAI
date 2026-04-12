# -*- coding: utf-8 -*-
"""
Collaboration Service for ComplyAI

This module handles:
- Real-time chat messaging for assessment collaboration
- User permissions and roles (Owner, Viewer)
- Message persistence and retrieval
- Report version tracking and invalidation
- Invite management
"""

import sqlite3
import json
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from pydantic import BaseModel, Field
import logging

logger = logging.getLogger(__name__)

# ============================================
# MODELS
# ============================================

class ParticipantRole(str, Enum):
    """Role enumeration for assessment participants."""
    OWNER = "owner"
    VIEWER = "viewer"
    EDITOR = "editor"  # Future support


class MessageType(str, Enum):
    """Message type enumeration."""
    TEXT = "text"
    SYSTEM = "system"
    NOTIFICATION = "notification"


class InviteStatus(str, Enum):
    """Invite status enumeration."""
    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ChatMessage(BaseModel):
    """Model for chat messages."""
    message_id: str = Field(..., description="Unique message identifier")
    session_id: str = Field(..., description="Assessment session ID")
    sender_id: int = Field(..., description="User ID of sender")
    sender_name: str = Field(..., description="Display name of sender")
    sender_role: ParticipantRole = Field(..., description="Role of sender")
    content: str = Field(..., description="Message content")
    message_type: MessageType = Field(default=MessageType.TEXT, description="Type of message")
    created_at: datetime = Field(default_factory=datetime.now, description="When message was sent")
    is_read: bool = Field(default=False, description="Whether message has been read")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class AssessmentParticipant(BaseModel):
    """Model for assessment participants."""
    participant_id: str = Field(..., description="Unique participant identifier")
    session_id: str = Field(..., description="Assessment session ID")
    user_id: int = Field(..., description="User ID")
    user_email: str = Field(..., description="User email")
    user_name: str = Field(..., description="User display name")
    role: ParticipantRole = Field(..., description="Participant role")
    joined_at: datetime = Field(default_factory=datetime.now, description="When participant joined")
    last_seen_at: Optional[datetime] = Field(None, description="Last activity timestamp")
    is_online: bool = Field(default=False, description="Online status")
    unread_count: int = Field(default=0, description="Unread message count")


class AssessmentInvite(BaseModel):
    """Model for assessment invitations."""
    invite_id: str = Field(..., description="Unique invite identifier")
    session_id: str = Field(..., description="Assessment session ID")
    inviter_id: int = Field(..., description="User ID of inviter")
    inviter_name: str = Field(..., description="Name of inviter")
    invitee_email: str = Field(..., description="Email of invitee")
    role: ParticipantRole = Field(default=ParticipantRole.VIEWER, description="Invited role")
    status: InviteStatus = Field(default=InviteStatus.PENDING, description="Invite status")
    invite_token: str = Field(..., description="Secure invite token")
    created_at: datetime = Field(default_factory=datetime.now, description="When invite was created")
    expires_at: datetime = Field(..., description="When invite expires")
    accepted_at: Optional[datetime] = Field(None, description="When invite was accepted")
    message: Optional[str] = Field(None, description="Personal invite message")


class ReportVersion(BaseModel):
    """Model for tracking report versions."""
    version_id: str = Field(..., description="Unique version identifier")
    report_id: str = Field(..., description="Report ID")
    session_id: str = Field(..., description="Session ID")
    version_number: int = Field(..., description="Incremental version number")
    created_at: datetime = Field(default_factory=datetime.now, description="Version creation time")
    created_by: int = Field(..., description="User ID who created version")
    change_type: str = Field(..., description="Type of change (input_update, regeneration)")
    change_summary: str = Field(..., description="Summary of changes")
    is_current: bool = Field(default=True, description="Whether this is current version")
    invalidated: bool = Field(default=False, description="Whether version is invalidated")


# ============================================
# COLLABORATION SERVICE
# ============================================

class CollaborationService:
    """Service for managing assessment collaboration, chat, and sharing."""
    
    def __init__(self, db_path: str = "project.db"):
        """Initialize the collaboration service."""
        self.db_path = db_path
        self._init_tables()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_tables(self):
        """Create collaboration tables if they don't exist."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Chat messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE NOT NULL,
                session_id TEXT NOT NULL,
                sender_id INTEGER NOT NULL,
                sender_name TEXT NOT NULL,
                sender_role TEXT NOT NULL,
                content TEXT NOT NULL,
                message_type TEXT DEFAULT 'text',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}',
                FOREIGN KEY(sender_id) REFERENCES users(id)
            )
        """)
        
        # Assessment participants table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessment_participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                participant_id TEXT UNIQUE NOT NULL,
                session_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                user_email TEXT NOT NULL,
                user_name TEXT NOT NULL,
                role TEXT NOT NULL,
                joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TEXT,
                is_online INTEGER DEFAULT 0,
                unread_count INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id),
                UNIQUE(session_id, user_id)
            )
        """)
        
        # Assessment invites table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessment_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invite_id TEXT UNIQUE NOT NULL,
                session_id TEXT NOT NULL,
                inviter_id INTEGER NOT NULL,
                inviter_name TEXT NOT NULL,
                invitee_email TEXT NOT NULL,
                role TEXT DEFAULT 'viewer',
                status TEXT DEFAULT 'pending',
                invite_token TEXT UNIQUE NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT NOT NULL,
                accepted_at TEXT,
                message TEXT,
                FOREIGN KEY(inviter_id) REFERENCES users(id)
            )
        """)
        
        # Report versions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version_id TEXT UNIQUE NOT NULL,
                report_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER NOT NULL,
                change_type TEXT NOT NULL,
                change_summary TEXT NOT NULL,
                is_current INTEGER DEFAULT 1,
                invalidated INTEGER DEFAULT 0,
                report_snapshot TEXT,
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
        """)
        
        # Message read status table (for tracking who read what)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message_read_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                read_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(message_id, user_id),
                FOREIGN KEY(message_id) REFERENCES chat_messages(message_id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        
        # Create indexes for performance (wrap in try/except for existing tables with different schema)
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_session ON chat_messages(session_id)")
        except sqlite3.OperationalError:
            pass  # Table may exist with different schema
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_created ON chat_messages(created_at)")
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_participants_session ON assessment_participants(session_id)")
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_invites_token ON assessment_invites(invite_token)")
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_versions_report ON report_versions(report_id)")
        except sqlite3.OperationalError:
            pass
        
        # ============================================
        # DIRECT MESSAGE TABLES
        # ============================================
        
        # Direct messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS direct_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE NOT NULL,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                attachment_url TEXT,
                attachment_type TEXT,
                attachment_name TEXT,
                is_deleted INTEGER DEFAULT 0,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(recipient_id) REFERENCES users(id)
            )
        """)
        
        # Add columns if they don't exist (for existing databases)
        try:
            cursor.execute("ALTER TABLE direct_messages ADD COLUMN attachment_url TEXT")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE direct_messages ADD COLUMN attachment_type TEXT")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE direct_messages ADD COLUMN attachment_name TEXT")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE direct_messages ADD COLUMN is_deleted INTEGER DEFAULT 0")
        except:
            pass
        
        # DM conversations table (tracks conversation metadata)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dm_conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1_id INTEGER NOT NULL,
                user2_id INTEGER NOT NULL,
                last_message_at TEXT DEFAULT CURRENT_TIMESTAMP,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user1_id) REFERENCES users(id),
                FOREIGN KEY(user2_id) REFERENCES users(id),
                UNIQUE(user1_id, user2_id)
            )
        """)
        
        # Indexes for DM performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dm_sender ON direct_messages(sender_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dm_recipient ON direct_messages(recipient_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dm_created ON direct_messages(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dm_conv_users ON dm_conversations(user1_id, user2_id)")
        
        conn.commit()
        conn.close()
    
    # ============================================
    # CHAT MESSAGE METHODS
    # ============================================
    
    def send_message(
        self,
        session_id: str,
        sender_id: int,
        sender_name: str,
        sender_role: str,
        content: str,
        message_type: str = "text",
        metadata: Dict[str, Any] = None
    ) -> ChatMessage:
        """
        Send a chat message.
        
        Args:
            session_id: Assessment session ID
            sender_id: User ID of sender
            sender_name: Display name of sender
            sender_role: Role of sender (owner/viewer)
            content: Message content
            message_type: Type of message (text/system/notification)
            metadata: Optional metadata
            
        Returns:
            ChatMessage object
        """
        message_id = f"msg_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now()
        metadata = metadata or {}
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO chat_messages 
            (message_id, session_id, sender_id, sender_name, sender_role, 
             content, message_type, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            message_id, session_id, sender_id, sender_name, sender_role,
            content, message_type, created_at.isoformat(), json.dumps(metadata)
        ))
        
        # Update unread count for other participants
        cursor.execute("""
            UPDATE assessment_participants 
            SET unread_count = unread_count + 1 
            WHERE session_id = ? AND user_id != ?
        """, (session_id, sender_id))
        
        conn.commit()
        conn.close()
        
        return ChatMessage(
            message_id=message_id,
            session_id=session_id,
            sender_id=sender_id,
            sender_name=sender_name,
            sender_role=ParticipantRole(sender_role),
            content=content,
            message_type=MessageType(message_type),
            created_at=created_at,
            metadata=metadata
        )
    
    def get_messages(
        self,
        session_id: str,
        limit: int = 50,
        before_timestamp: Optional[datetime] = None,
        after_timestamp: Optional[datetime] = None
    ) -> List[ChatMessage]:
        """
        Get chat messages for a session.
        
        Args:
            session_id: Assessment session ID
            limit: Maximum number of messages to return
            before_timestamp: Get messages before this time
            after_timestamp: Get messages after this time
            
        Returns:
            List of ChatMessage objects
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM chat_messages WHERE session_id = ?"
        params = [session_id]
        
        if before_timestamp:
            query += " AND created_at < ?"
            params.append(before_timestamp.isoformat())
        
        if after_timestamp:
            query += " AND created_at > ?"
            params.append(after_timestamp.isoformat())
        
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        messages = []
        for row in reversed(rows):  # Reverse to get chronological order
            messages.append(ChatMessage(
                message_id=row['message_id'],
                session_id=row['session_id'],
                sender_id=row['sender_id'],
                sender_name=row['sender_name'],
                sender_role=ParticipantRole(row['sender_role']),
                content=row['content'],
                message_type=MessageType(row['message_type']),
                created_at=datetime.fromisoformat(row['created_at']),
                is_read=bool(row['is_read']),
                metadata=json.loads(row['metadata'] or '{}')
            ))
        
        return messages
    
    def mark_messages_read(self, session_id: str, user_id: int, up_to_message_id: Optional[str] = None) -> int:
        """
        Mark messages as read for a user.
        
        Args:
            session_id: Assessment session ID
            user_id: User ID
            up_to_message_id: Mark all messages up to and including this message
            
        Returns:
            Number of messages marked as read
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Get all unread messages for this session
        if up_to_message_id:
            cursor.execute("""
                SELECT message_id FROM chat_messages 
                WHERE session_id = ? AND sender_id != ?
                AND message_id NOT IN (
                    SELECT message_id FROM message_read_status WHERE user_id = ?
                )
                AND created_at <= (
                    SELECT created_at FROM chat_messages WHERE message_id = ?
                )
            """, (session_id, user_id, user_id, up_to_message_id))
        else:
            cursor.execute("""
                SELECT message_id FROM chat_messages 
                WHERE session_id = ? AND sender_id != ?
                AND message_id NOT IN (
                    SELECT message_id FROM message_read_status WHERE user_id = ?
                )
            """, (session_id, user_id, user_id))
        
        unread_messages = cursor.fetchall()
        count = 0
        
        for row in unread_messages:
            try:
                cursor.execute("""
                    INSERT INTO message_read_status (message_id, user_id)
                    VALUES (?, ?)
                """, (row['message_id'], user_id))
                count += 1
            except sqlite3.IntegrityError:
                pass  # Already marked as read
        
        # Reset unread count for this participant
        cursor.execute("""
            UPDATE assessment_participants 
            SET unread_count = 0 
            WHERE session_id = ? AND user_id = ?
        """, (session_id, user_id))
        
        conn.commit()
        conn.close()
        
        return count
    
    def get_unread_count(self, session_id: str, user_id: int) -> int:
        """Get unread message count for a user in a session."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT unread_count FROM assessment_participants 
            WHERE session_id = ? AND user_id = ?
        """, (session_id, user_id))
        
        row = cursor.fetchone()
        conn.close()
        
        return row['unread_count'] if row else 0
    
    # ============================================
    # PARTICIPANT METHODS
    # ============================================
    
    def add_participant(
        self,
        session_id: str,
        user_id: int,
        user_email: str,
        user_name: str,
        role: str = "viewer"
    ) -> AssessmentParticipant:
        """
        Add a participant to an assessment.
        
        Args:
            session_id: Assessment session ID
            user_id: User ID
            user_email: User email
            user_name: User display name
            role: Participant role (owner/viewer)
            
        Returns:
            AssessmentParticipant object
        """
        participant_id = f"part_{uuid.uuid4().hex[:12]}"
        joined_at = datetime.now()
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO assessment_participants 
                (participant_id, session_id, user_id, user_email, user_name, role, joined_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (participant_id, session_id, user_id, user_email, user_name, role, joined_at.isoformat()))
            
            conn.commit()
        except sqlite3.IntegrityError:
            # Participant already exists, update their info
            cursor.execute("""
                UPDATE assessment_participants 
                SET user_name = ?, last_seen_at = ?
                WHERE session_id = ? AND user_id = ?
            """, (user_name, joined_at.isoformat(), session_id, user_id))
            
            cursor.execute("""
                SELECT participant_id FROM assessment_participants 
                WHERE session_id = ? AND user_id = ?
            """, (session_id, user_id))
            row = cursor.fetchone()
            participant_id = row['participant_id']
            
            conn.commit()
        
        conn.close()
        
        return AssessmentParticipant(
            participant_id=participant_id,
            session_id=session_id,
            user_id=user_id,
            user_email=user_email,
            user_name=user_name,
            role=ParticipantRole(role),
            joined_at=joined_at
        )
    
    def get_participants(self, session_id: str) -> List[AssessmentParticipant]:
        """Get all participants for an assessment."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM assessment_participants WHERE session_id = ?
        """, (session_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        participants = []
        for row in rows:
            participants.append(AssessmentParticipant(
                participant_id=row['participant_id'],
                session_id=row['session_id'],
                user_id=row['user_id'],
                user_email=row['user_email'],
                user_name=row['user_name'],
                role=ParticipantRole(row['role']),
                joined_at=datetime.fromisoformat(row['joined_at']),
                last_seen_at=datetime.fromisoformat(row['last_seen_at']) if row['last_seen_at'] else None,
                is_online=bool(row['is_online']),
                unread_count=row['unread_count']
            ))
        
        return participants
    
    def update_participant_status(self, session_id: str, user_id: int, is_online: bool):
        """Update participant online status."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE assessment_participants 
            SET is_online = ?, last_seen_at = ?
            WHERE session_id = ? AND user_id = ?
        """, (int(is_online), datetime.now().isoformat(), session_id, user_id))
        
        conn.commit()
        conn.close()
    
    def check_permission(self, session_id: str, user_id: int, required_role: str = "viewer") -> Tuple[bool, Optional[str]]:
        """
        Check if user has permission to access session.
        
        Args:
            session_id: Assessment session ID
            user_id: User ID to check
            required_role: Minimum required role
            
        Returns:
            Tuple of (has_permission, actual_role)
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT role FROM assessment_participants 
            WHERE session_id = ? AND user_id = ?
        """, (session_id, user_id))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return False, None
        
        role = row['role']
        role_hierarchy = {'viewer': 1, 'editor': 2, 'owner': 3}
        
        has_permission = role_hierarchy.get(role, 0) >= role_hierarchy.get(required_role, 0)
        return has_permission, role
    
    # ============================================
    # INVITE METHODS
    # ============================================
    
    def create_invite(
        self,
        session_id: str,
        inviter_id: int,
        inviter_name: str,
        invitee_email: str,
        role: str = "viewer",
        expires_in_days: int = 7,
        message: Optional[str] = None
    ) -> AssessmentInvite:
        """
        Create an invitation to collaborate on an assessment.
        
        Args:
            session_id: Assessment session ID
            inviter_id: User ID of inviter
            inviter_name: Name of inviter
            invitee_email: Email of invitee
            role: Role to grant (viewer/editor)
            expires_in_days: Days until invite expires
            message: Personal invite message
            
        Returns:
            AssessmentInvite object
        """
        invite_id = f"inv_{uuid.uuid4().hex[:12]}"
        invite_token = hashlib.sha256(f"{invite_id}{session_id}{datetime.now().isoformat()}".encode()).hexdigest()[:32]
        created_at = datetime.now()
        expires_at = created_at + timedelta(days=expires_in_days)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Check if invite already exists and is pending
        cursor.execute("""
            SELECT invite_id, status FROM assessment_invites 
            WHERE session_id = ? AND invitee_email = ? AND status = 'pending'
        """, (session_id, invitee_email))
        
        existing = cursor.fetchone()
        if existing:
            # Revoke existing invite and create new one
            cursor.execute("""
                UPDATE assessment_invites SET status = 'revoked' WHERE invite_id = ?
            """, (existing['invite_id'],))
        
        cursor.execute("""
            INSERT INTO assessment_invites 
            (invite_id, session_id, inviter_id, inviter_name, invitee_email, 
             role, invite_token, created_at, expires_at, message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            invite_id, session_id, inviter_id, inviter_name, invitee_email,
            role, invite_token, created_at.isoformat(), expires_at.isoformat(), message
        ))
        
        conn.commit()
        conn.close()
        
        return AssessmentInvite(
            invite_id=invite_id,
            session_id=session_id,
            inviter_id=inviter_id,
            inviter_name=inviter_name,
            invitee_email=invitee_email,
            role=ParticipantRole(role),
            status=InviteStatus.PENDING,
            invite_token=invite_token,
            created_at=created_at,
            expires_at=expires_at,
            message=message
        )
    
    def accept_invite(self, invite_token: str, user_id: int, user_name: str, user_email: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Accept an invitation.
        
        Args:
            invite_token: Invite token
            user_id: User ID accepting invite
            user_name: User name
            user_email: User email
            
        Returns:
            Tuple of (success, session_id, error_message)
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM assessment_invites WHERE invite_token = ?
        """, (invite_token,))
        
        invite = cursor.fetchone()
        
        if not invite:
            conn.close()
            return False, None, "Invite not found"
        
        if invite['status'] != 'pending':
            conn.close()
            return False, None, f"Invite is {invite['status']}"
        
        if datetime.fromisoformat(invite['expires_at']) < datetime.now():
            cursor.execute("""
                UPDATE assessment_invites SET status = 'expired' WHERE invite_id = ?
            """, (invite['invite_id'],))
            conn.commit()
            conn.close()
            return False, None, "Invite has expired"
        
        # Accept invite and add participant
        cursor.execute("""
            UPDATE assessment_invites 
            SET status = 'accepted', accepted_at = ?
            WHERE invite_id = ?
        """, (datetime.now().isoformat(), invite['invite_id']))
        
        conn.commit()
        conn.close()
        
        # Add participant
        self.add_participant(
            session_id=invite['session_id'],
            user_id=user_id,
            user_email=user_email,
            user_name=user_name,
            role=invite['role']
        )
        
        # Send system message about new participant
        self.send_message(
            session_id=invite['session_id'],
            sender_id=0,  # System
            sender_name="System",
            sender_role="owner",
            content=f"{user_name} joined the assessment",
            message_type="system"
        )
        
        return True, invite['session_id'], None
    
    def get_pending_invites(self, session_id: str) -> List[AssessmentInvite]:
        """Get all pending invites for a session."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM assessment_invites 
            WHERE session_id = ? AND status = 'pending'
        """, (session_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        invites = []
        for row in rows:
            invites.append(AssessmentInvite(
                invite_id=row['invite_id'],
                session_id=row['session_id'],
                inviter_id=row['inviter_id'],
                inviter_name=row['inviter_name'],
                invitee_email=row['invitee_email'],
                role=ParticipantRole(row['role']),
                status=InviteStatus(row['status']),
                invite_token=row['invite_token'],
                created_at=datetime.fromisoformat(row['created_at']),
                expires_at=datetime.fromisoformat(row['expires_at']),
                message=row['message']
            ))
        
        return invites
    
    def revoke_invite(self, invite_id: str, user_id: int) -> bool:
        """Revoke an invitation (owner only)."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Check if user is owner
        cursor.execute("""
            SELECT i.session_id FROM assessment_invites i
            JOIN assessment_participants p ON i.session_id = p.session_id
            WHERE i.invite_id = ? AND p.user_id = ? AND p.role = 'owner'
        """, (invite_id, user_id))
        
        if not cursor.fetchone():
            conn.close()
            return False
        
        cursor.execute("""
            UPDATE assessment_invites SET status = 'revoked' WHERE invite_id = ?
        """, (invite_id,))
        
        conn.commit()
        conn.close()
        return True
    
    # ============================================
    # REPORT VERSION METHODS
    # ============================================
    
    def create_report_version(
        self,
        report_id: str,
        session_id: str,
        created_by: int,
        change_type: str,
        change_summary: str,
        report_snapshot: Optional[str] = None
    ) -> ReportVersion:
        """
        Create a new report version.
        
        Args:
            report_id: Report ID
            session_id: Session ID
            created_by: User ID who created version
            change_type: Type of change
            change_summary: Summary of changes
            report_snapshot: Optional JSON snapshot of report
            
        Returns:
            ReportVersion object
        """
        version_id = f"ver_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now()
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Get current version number
        cursor.execute("""
            SELECT MAX(version_number) as max_ver FROM report_versions 
            WHERE report_id = ?
        """, (report_id,))
        
        row = cursor.fetchone()
        version_number = (row['max_ver'] or 0) + 1
        
        # Mark previous versions as not current
        cursor.execute("""
            UPDATE report_versions SET is_current = 0 WHERE report_id = ?
        """, (report_id,))
        
        # Insert new version
        cursor.execute("""
            INSERT INTO report_versions 
            (version_id, report_id, session_id, version_number, created_at, 
             created_by, change_type, change_summary, report_snapshot)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            version_id, report_id, session_id, version_number, created_at.isoformat(),
            created_by, change_type, change_summary, report_snapshot
        ))
        
        conn.commit()
        conn.close()
        
        # Notify participants about new version
        self.send_message(
            session_id=session_id,
            sender_id=0,
            sender_name="System",
            sender_role="owner",
            content=f"Report updated to version {version_number}: {change_summary}",
            message_type="notification",
            metadata={"version_id": version_id, "report_id": report_id}
        )
        
        return ReportVersion(
            version_id=version_id,
            report_id=report_id,
            session_id=session_id,
            version_number=version_number,
            created_at=created_at,
            created_by=created_by,
            change_type=change_type,
            change_summary=change_summary,
            is_current=True
        )
    
    def get_report_versions(self, report_id: str) -> List[ReportVersion]:
        """Get all versions of a report."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM report_versions WHERE report_id = ? ORDER BY version_number DESC
        """, (report_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        versions = []
        for row in rows:
            versions.append(ReportVersion(
                version_id=row['version_id'],
                report_id=row['report_id'],
                session_id=row['session_id'],
                version_number=row['version_number'],
                created_at=datetime.fromisoformat(row['created_at']),
                created_by=row['created_by'],
                change_type=row['change_type'],
                change_summary=row['change_summary'],
                is_current=bool(row['is_current']),
                invalidated=bool(row['invalidated'])
            ))
        
        return versions
    
    def invalidate_report(self, session_id: str, reason: str) -> bool:
        """
        Invalidate current report version when inputs change.
        
        Args:
            session_id: Session ID
            reason: Reason for invalidation
            
        Returns:
            True if a report was invalidated
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE report_versions 
            SET invalidated = 1 
            WHERE session_id = ? AND is_current = 1
        """, (session_id,))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if affected > 0:
            # Notify about invalidation
            self.send_message(
                session_id=session_id,
                sender_id=0,
                sender_name="System",
                sender_role="owner",
                content=f"Report invalidated: {reason}. Regeneration required.",
                message_type="notification"
            )
        
        return affected > 0
    
    def get_current_version(self, report_id: str) -> Optional[ReportVersion]:
        """Get the current version of a report."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM report_versions 
            WHERE report_id = ? AND is_current = 1
        """, (report_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return ReportVersion(
            version_id=row['version_id'],
            report_id=row['report_id'],
            session_id=row['session_id'],
            version_number=row['version_number'],
            created_at=datetime.fromisoformat(row['created_at']),
            created_by=row['created_by'],
            change_type=row['change_type'],
            change_summary=row['change_summary'],
            is_current=True,
            invalidated=bool(row['invalidated'])
        )
    
    # ============================================
    # DIRECT MESSAGE METHODS
    # ============================================
    
    def send_direct_message(
        self,
        sender_id: int,
        recipient_id: int,
        content: str,
        attachment_url: str = None,
        attachment_type: str = None,
        attachment_name: str = None
    ) -> Dict[str, Any]:
        """
        Send a direct message between users.
        
        Args:
            sender_id: User ID of sender
            recipient_id: User ID of recipient
            content: Message content
            attachment_url: Optional attachment URL
            attachment_type: Optional attachment type (image/file)
            attachment_name: Optional attachment filename
            
        Returns:
            Message data dict
        """
        message_id = f"dm_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now()
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Insert the message
        cursor.execute("""
            INSERT INTO direct_messages 
            (message_id, sender_id, recipient_id, content, created_at, attachment_url, attachment_type, attachment_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (message_id, sender_id, recipient_id, content, created_at.isoformat(), attachment_url, attachment_type, attachment_name))
        
        # Get the inserted row ID
        row_id = cursor.lastrowid
        
        # Update or create conversation
        # Always store with smaller user_id as user1_id for consistency
        user1 = min(sender_id, recipient_id)
        user2 = max(sender_id, recipient_id)
        
        cursor.execute("""
            INSERT INTO dm_conversations (user1_id, user2_id, last_message_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user1_id, user2_id) DO UPDATE SET last_message_at = ?
        """, (user1, user2, created_at.isoformat(), created_at.isoformat()))
        
        conn.commit()
        conn.close()
        
        return {
            'id': row_id,
            'message_id': message_id,
            'sender_id': sender_id,
            'recipient_id': recipient_id,
            'content': content,
            'created_at': created_at.isoformat(),
            'is_read': False,
            'attachment_url': attachment_url,
            'attachment_type': attachment_type,
            'attachment_name': attachment_name,
            'is_deleted': 0
        }
    
    def get_dm_conversations(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get all DM conversations for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of conversation dicts with user info and last message
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Get conversations where user is participant
        cursor.execute("""
            SELECT 
                c.id,
                c.user1_id,
                c.user2_id,
                c.last_message_at,
                CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END as other_user_id
            FROM dm_conversations c
            WHERE c.user1_id = ? OR c.user2_id = ?
            ORDER BY c.last_message_at DESC
        """, (user_id, user_id, user_id))
        
        conversations = []
        for row in cursor.fetchall():
            other_user_id = row['other_user_id']
            
            # Get other user's info
            cursor.execute("SELECT id, full_name, email FROM users WHERE id = ?", (other_user_id,))
            user_row = cursor.fetchone()
            
            if not user_row:
                continue
            
            # Get last message
            cursor.execute("""
                SELECT content, sender_id, created_at, is_deleted, attachment_url, attachment_type FROM direct_messages
                WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
                ORDER BY created_at DESC LIMIT 1
            """, (user_id, other_user_id, other_user_id, user_id))
            last_msg = cursor.fetchone()
            
            # Determine last message preview text
            last_message_text = None
            if last_msg:
                last_msg_dict = dict(last_msg)
                if last_msg_dict.get('is_deleted'):
                    last_message_text = 'Message deleted'
                elif last_msg_dict.get('content'):
                    last_message_text = last_msg_dict['content']
                elif last_msg_dict.get('attachment_url'):
                    if last_msg_dict.get('attachment_type') == 'image':
                        last_message_text = '📷 Photo'
                    else:
                        last_message_text = '📎 File'
                else:
                    last_message_text = 'New message'
            
            # Get unread count
            cursor.execute("""
                SELECT COUNT(*) FROM direct_messages
                WHERE sender_id = ? AND recipient_id = ? AND is_read = 0
            """, (other_user_id, user_id))
            unread = cursor.fetchone()[0]
            
            conversations.append({
                'user_id': other_user_id,
                'user_name': user_row['full_name'],
                'user_email': user_row['email'],
                'last_message': last_message_text,
                'last_message_at': last_msg['created_at'] if last_msg else row['last_message_at'],
                'unread_count': unread
            })
        
        conn.close()
        return conversations
    
    def get_dm_messages(
        self,
        user_id: int,
        other_user_id: int,
        limit: int = 50,
        before_timestamp: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get DM messages between two users.
        
        Args:
            user_id: Current user ID
            other_user_id: Other user ID
            limit: Max messages to return
            before_timestamp: Get messages before this time
            
        Returns:
            List of message dicts
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT dm.*, u.full_name as sender_name
            FROM direct_messages dm
            JOIN users u ON dm.sender_id = u.id
            WHERE (dm.sender_id = ? AND dm.recipient_id = ?) 
               OR (dm.sender_id = ? AND dm.recipient_id = ?)
        """
        params = [user_id, other_user_id, other_user_id, user_id]
        
        if before_timestamp:
            query += " AND dm.created_at < ?"
            params.append(before_timestamp)
        
        query += " ORDER BY dm.created_at DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        messages = []
        for row in reversed(rows):  # Reverse for chronological order
            row_dict = dict(row)  # Convert Row to dict for .get() support
            messages.append({
                'id': row_dict['id'],
                'message_id': row_dict['message_id'],
                'sender_id': row_dict['sender_id'],
                'sender_name': row_dict['sender_name'],
                'recipient_id': row_dict['recipient_id'],
                'content': row_dict['content'] if not row_dict.get('is_deleted') else '',
                'created_at': row_dict['created_at'],
                'is_read': bool(row_dict['is_read']),
                'attachment_url': row_dict.get('attachment_url'),
                'attachment_type': row_dict.get('attachment_type'),
                'attachment_name': row_dict.get('attachment_name'),
                'is_deleted': row_dict.get('is_deleted', 0)
            })
        
        return messages
    
    def delete_dm_message(self, message_id: int, user_id: int) -> bool:
        """
        Soft delete a DM message (only the sender can delete).
        
        Args:
            message_id: The message row ID
            user_id: The user requesting deletion
            
        Returns:
            True if deleted, False otherwise
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Only allow sender to delete their own messages
        cursor.execute("""
            UPDATE direct_messages 
            SET is_deleted = 1, content = '', attachment_url = NULL
            WHERE id = ? AND sender_id = ?
        """, (message_id, user_id))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success
    
    def clear_dm_conversation(self, user_id: int, other_user_id: int) -> int:
        """
        Clear all messages in a DM conversation.
        
        Args:
            user_id: Current user ID
            other_user_id: Other user ID
            
        Returns:
            Number of messages deleted
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Soft delete all messages in the conversation
        cursor.execute("""
            UPDATE direct_messages 
            SET is_deleted = 1, content = '', attachment_url = NULL
            WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
        """, (user_id, other_user_id, other_user_id, user_id))
        
        count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return count
    
    def mark_dm_messages_read(self, user_id: int, sender_id: int) -> int:
        """
        Mark all DM messages from a sender as read.
        
        Args:
            user_id: Current user ID (recipient)
            sender_id: Sender user ID
            
        Returns:
            Number of messages marked as read
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE direct_messages 
            SET is_read = 1 
            WHERE sender_id = ? AND recipient_id = ? AND is_read = 0
        """, (sender_id, user_id))
        
        count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return count
    
    def get_dm_unread_total(self, user_id: int) -> int:
        """Get total unread DM count for a user."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT COUNT(*) FROM direct_messages
            WHERE recipient_id = ? AND is_read = 0
        """, (user_id,))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all users for DM user selection."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, full_name, email, role FROM users ORDER BY full_name")
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': row['id'],
                'full_name': row['full_name'],
                'email': row['email'],
                'role': row['role']
            }
            for row in rows
        ]


# Singleton instance
_collaboration_service = None

def get_collaboration_service(db_path: str = "project.db") -> CollaborationService:
    """Get or create the collaboration service singleton."""
    global _collaboration_service
    if _collaboration_service is None:
        _collaboration_service = CollaborationService(db_path)
    return _collaboration_service
