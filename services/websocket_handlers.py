# -*- coding: utf-8 -*-
"""
WebSocket Event Handlers for Real-Time Collaboration

This module handles:
- Real-time chat messaging via WebSocket
- Participant presence (online/offline status)
- Report update notifications
- Session connection management
"""

from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask import request, session
from datetime import datetime
import logging
from typing import Dict, Set

logger = logging.getLogger(__name__)

# Track connected users per session
# Format: {session_id: {user_id: {sid: socket_id, ...}}}
CONNECTED_USERS: Dict[str, Dict[int, Dict]] = {}

# Track socket ID to user mapping
SID_TO_USER: Dict[str, Dict] = {}


def init_socketio(app, collaboration_service):
    """
    Initialize Flask-SocketIO with event handlers.
    
    Args:
        app: Flask application
        collaboration_service: CollaborationService instance
        
    Returns:
        SocketIO instance
    """
    socketio = SocketIO(
        app, 
        cors_allowed_origins="*",
        async_mode='threading',
        ping_timeout=60,
        ping_interval=25
    )
    
    @socketio.on('connect')
    def handle_connect():
        """Handle new WebSocket connection."""
        logger.info(f"Client connected: {request.sid}")
        emit('connected', {'status': 'connected', 'sid': request.sid})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle WebSocket disconnection."""
        sid = request.sid
        logger.info(f"Client disconnected: {sid}")
        
        # Clean up user tracking
        if sid in SID_TO_USER:
            user_info = SID_TO_USER[sid]
            session_id = user_info.get('session_id')
            user_id = user_info.get('user_id')
            
            if session_id and user_id:
                # Remove from connected users
                if session_id in CONNECTED_USERS:
                    if user_id in CONNECTED_USERS[session_id]:
                        del CONNECTED_USERS[session_id][user_id]
                    
                    # Update online status
                    collaboration_service.update_participant_status(session_id, user_id, False)
                    
                    # Notify others
                    emit('user_left', {
                        'user_id': user_id,
                        'user_name': user_info.get('user_name', 'Unknown'),
                        'timestamp': datetime.now().isoformat()
                    }, room=session_id)
            
            del SID_TO_USER[sid]
    
    @socketio.on('join_session')
    def handle_join_session(data):
        """
        Handle user joining a chat session.
        
        Expected data:
        {
            "session_id": "session_xxx",
            "user_id": 123,
            "user_name": "John Doe",
            "user_email": "john@example.com",
            "role": "owner|viewer"
        }
        """
        session_id = data.get('session_id')
        user_id = data.get('user_id')
        user_name = data.get('user_name', 'Unknown')
        user_email = data.get('user_email', '')
        role = data.get('role', 'viewer')
        sid = request.sid
        
        if not session_id or not user_id:
            emit('error', {'message': 'Missing session_id or user_id'})
            return
        
        # Check permission
        has_permission, actual_role = collaboration_service.check_permission(session_id, user_id)
        if not has_permission:
            # Auto-add owner if this is their session (session_id starts with their info)
            if role == 'owner' or session_id.startswith(f'session_'):
                collaboration_service.add_participant(
                    session_id=session_id,
                    user_id=user_id,
                    user_email=user_email,
                    user_name=user_name,
                    role=role
                )
                actual_role = role
            else:
                emit('error', {'message': 'Access denied'})
                return
        else:
            role = actual_role
        
        # Join the socket room
        join_room(session_id)
        
        # Track connected user
        if session_id not in CONNECTED_USERS:
            CONNECTED_USERS[session_id] = {}
        
        CONNECTED_USERS[session_id][user_id] = {
            'sid': sid,
            'user_name': user_name,
            'role': role,
            'joined_at': datetime.now().isoformat()
        }
        
        SID_TO_USER[sid] = {
            'session_id': session_id,
            'user_id': user_id,
            'user_name': user_name,
            'role': role
        }
        
        # Update online status
        collaboration_service.update_participant_status(session_id, user_id, True)
        
        # Get recent messages
        messages = collaboration_service.get_messages(session_id, limit=50)
        messages_data = [
            {
                'message_id': msg.message_id,
                'sender_id': msg.sender_id,
                'sender_name': msg.sender_name,
                'sender_role': msg.sender_role.value,
                'content': msg.content,
                'message_type': msg.message_type.value,
                'created_at': msg.created_at.isoformat(),
                'metadata': msg.metadata
            }
            for msg in messages
        ]
        
        # Get participants
        participants = collaboration_service.get_participants(session_id)
        participants_data = [
            {
                'user_id': p.user_id,
                'user_name': p.user_name,
                'role': p.role.value,
                'is_online': p.user_id in CONNECTED_USERS.get(session_id, {}),
                'unread_count': p.unread_count
            }
            for p in participants
        ]
        
        # Get unread count
        unread_count = collaboration_service.get_unread_count(session_id, user_id)
        
        # Send session data to joining user
        emit('session_joined', {
            'session_id': session_id,
            'user_id': user_id,
            'role': role,
            'messages': messages_data,
            'participants': participants_data,
            'unread_count': unread_count
        })
        
        # Notify others about new user
        emit('user_joined', {
            'user_id': user_id,
            'user_name': user_name,
            'role': role,
            'timestamp': datetime.now().isoformat()
        }, room=session_id, include_self=False)
        
        logger.info(f"User {user_name} (ID: {user_id}) joined session {session_id}")
    
    @socketio.on('leave_session')
    def handle_leave_session(data):
        """Handle user leaving a chat session."""
        session_id = data.get('session_id')
        user_id = data.get('user_id')
        sid = request.sid
        
        if session_id:
            leave_room(session_id)
            
            if session_id in CONNECTED_USERS and user_id in CONNECTED_USERS[session_id]:
                user_info = CONNECTED_USERS[session_id][user_id]
                del CONNECTED_USERS[session_id][user_id]
                
                # Update online status
                collaboration_service.update_participant_status(session_id, user_id, False)
                
                # Notify others
                emit('user_left', {
                    'user_id': user_id,
                    'user_name': user_info.get('user_name', 'Unknown'),
                    'timestamp': datetime.now().isoformat()
                }, room=session_id)
        
        if sid in SID_TO_USER:
            del SID_TO_USER[sid]
    
    @socketio.on('send_message')
    def handle_send_message(data):
        """
        Handle sending a chat message.
        
        Expected data:
        {
            "session_id": "session_xxx",
            "user_id": 123,
            "user_name": "John Doe",
            "role": "owner|viewer",
            "content": "Hello everyone!",
            "message_type": "text"  // optional, defaults to "text"
        }
        """
        session_id = data.get('session_id')
        user_id = data.get('user_id')
        user_name = data.get('user_name', 'Unknown')
        role = data.get('role', 'viewer')
        content = data.get('content', '').strip()
        message_type = data.get('message_type', 'text')
        
        if not session_id or not user_id or not content:
            emit('error', {'message': 'Missing required fields'})
            return
        
        # Check permission
        has_permission, _ = collaboration_service.check_permission(session_id, user_id)
        if not has_permission:
            emit('error', {'message': 'Access denied'})
            return
        
        # Save message
        message = collaboration_service.send_message(
            session_id=session_id,
            sender_id=user_id,
            sender_name=user_name,
            sender_role=role,
            content=content,
            message_type=message_type
        )
        
        # Broadcast to all participants in the session
        message_data = {
            'message_id': message.message_id,
            'session_id': session_id,
            'sender_id': user_id,
            'sender_name': user_name,
            'sender_role': role,
            'content': content,
            'message_type': message_type,
            'created_at': message.created_at.isoformat()
        }
        
        emit('new_message', message_data, room=session_id)
        
        logger.debug(f"Message sent in session {session_id} by {user_name}")
    
    @socketio.on('mark_read')
    def handle_mark_read(data):
        """Handle marking messages as read."""
        session_id = data.get('session_id')
        user_id = data.get('user_id')
        message_id = data.get('message_id')  # Optional: mark up to this message
        
        if not session_id or not user_id:
            return
        
        count = collaboration_service.mark_messages_read(session_id, user_id, message_id)
        
        emit('messages_read', {
            'session_id': session_id,
            'user_id': user_id,
            'count': count
        })
    
    @socketio.on('typing')
    def handle_typing(data):
        """Handle typing indicator."""
        session_id = data.get('session_id')
        user_id = data.get('user_id')
        user_name = data.get('user_name', 'Someone')
        is_typing = data.get('is_typing', True)
        
        if not session_id:
            return
        
        emit('user_typing', {
            'user_id': user_id,
            'user_name': user_name,
            'is_typing': is_typing
        }, room=session_id, include_self=False)
    
    @socketio.on('report_updated')
    def handle_report_updated(data):
        """
        Handle report update notification.
        
        This is called when the owner updates report inputs,
        triggering a notification to all viewers.
        """
        session_id = data.get('session_id')
        user_id = data.get('user_id')
        change_type = data.get('change_type', 'update')
        change_summary = data.get('change_summary', 'Report updated')
        
        if not session_id or not user_id:
            return
        
        # Check if user is owner
        has_permission, role = collaboration_service.check_permission(session_id, user_id, 'owner')
        if not has_permission:
            emit('error', {'message': 'Only owner can update report'})
            return
        
        # Notify all participants
        emit('report_update_notification', {
            'session_id': session_id,
            'change_type': change_type,
            'change_summary': change_summary,
            'updated_by': user_id,
            'timestamp': datetime.now().isoformat()
        }, room=session_id)
    
    @socketio.on('get_online_users')
    def handle_get_online_users(data):
        """Get list of online users in a session."""
        session_id = data.get('session_id')
        
        if not session_id:
            return
        
        online_users = []
        if session_id in CONNECTED_USERS:
            for user_id, user_info in CONNECTED_USERS[session_id].items():
                online_users.append({
                    'user_id': user_id,
                    'user_name': user_info.get('user_name'),
                    'role': user_info.get('role'),
                    'joined_at': user_info.get('joined_at')
                })
        
        emit('online_users', {
            'session_id': session_id,
            'users': online_users
        })
    
    return socketio


def broadcast_to_session(socketio, session_id: str, event: str, data: dict):
    """
    Broadcast an event to all connected users in a session.
    
    Args:
        socketio: SocketIO instance
        session_id: Session ID
        event: Event name
        data: Event data
    """
    socketio.emit(event, data, room=session_id)


def notify_report_regeneration(socketio, session_id: str, report_id: str, status: str, data: dict = None):
    """
    Notify all participants about report regeneration progress.
    
    Args:
        socketio: SocketIO instance
        session_id: Session ID
        report_id: Report ID
        status: Status (started, progress, completed, error)
        data: Additional data
    """
    socketio.emit('report_regeneration', {
        'session_id': session_id,
        'report_id': report_id,
        'status': status,
        'timestamp': datetime.now().isoformat(),
        **(data or {})
    }, room=session_id)
