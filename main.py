from flask import Flask, render_template, request, redirect, url_for, session
from markupsafe import escape
from flask_socketio import SocketIO, join_room, leave_room, send, emit
import random
import uuid
import time
from threading import Thread
from bleach import clean
import re
import hashlib
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Security Constants
MAX_MESSAGE_LENGTH = 1000  # Maximum characters per message
ALLOWED_HTML_TAGS = ['b', 'i', 'em', 'strong', 'a']  # Limited safe HTML tags
ALLOWED_HTML_ATTRIBUTES = {'a': ['href', 'title']}  # Limited attributes for links

# Additional Security Constants
MAX_ROOMS = 100  # Maximum number of rooms allowed
MAX_MESSAGES_PER_ROOM = 1000  # Maximum messages stored per room
ROOM_EXPIRY_TIME = 24 * 60 * 60  # Room expires after 24 hours
MAX_ROOMS_PER_IP = 3  # Maximum rooms an IP can create
CLEANUP_INTERVAL = 300  # Cleanup every 5 minutes

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')  # Get secret key from environment variable
socketio = SocketIO(app)

rooms = {}

def generate_temp_room_code():
    # Generate a random 6-digit number
    return f"{random.randint(100000, 999999)}"

def cleanup_rooms():
    """Remove expired rooms and enforce limits"""
    current_time = time.time()
    rooms_to_remove = []
    
    for room_id, room_data in rooms.items():
        # Check room expiry
        if current_time - room_data['created_at'] > ROOM_EXPIRY_TIME:
            rooms_to_remove.append(room_id)
            continue
            
        # Trim messages if they exceed limit
        if len(room_data['messages']) > MAX_MESSAGES_PER_ROOM:
            room_data['messages'] = room_data['messages'][-MAX_MESSAGES_PER_ROOM:]
    
    # Remove expired rooms
    for room_id in rooms_to_remove:
        socketio.emit('room_expired', room=room_id)
        rooms.pop(room_id, None)

def start_background_task():
    def background_jobs():
        while True:
            current_time = int(time.time())
            
            # Update room codes
            for room_id in list(rooms.keys()):  # Use list to avoid runtime modification issues
                if room_id in rooms:  # Check if room still exists
                    rooms[room_id]['current_code'] = generate_temp_room_code()
                    rooms[room_id]['last_code_update'] = current_time
                    socketio.emit('code_update', {
                        'new_code': rooms[room_id]['current_code']
                    }, room=room_id)
            
            # Run cleanup
            cleanup_rooms()
            
            time.sleep(CLEANUP_INTERVAL)

    thread = Thread(target=background_jobs)
    thread.daemon = True
    thread.start()

start_background_task()

def sanitize_message(message):
    if not isinstance(message, str):
        return ""
    
    # Truncate message if it exceeds maximum length
    if len(message) > MAX_MESSAGE_LENGTH:
        message = message[:MAX_MESSAGE_LENGTH] + "... (message truncated)"
    
    # Clean the message with specific allowed tags and attributes
    cleaned_message = clean(
        message,
        tags=ALLOWED_HTML_TAGS,
        attributes=ALLOWED_HTML_ATTRIBUTES,
        strip=True,
        strip_comments=True
    )
    
    return cleaned_message

def validate_display_name(name):
    if not isinstance(name, str):
        return False
    return bool(re.match("^[a-zA-Z0-9_-]{3,20}$", name))

def validate_room_code(code):
    if not isinstance(code, str):
        return False
    return bool(re.match("^[0-9]{6}$", code))

def hash_ip(ip):
    """Hash IP address with SHA-256"""
    return hashlib.sha256(ip.encode()).hexdigest()

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        display_name = request.form.get("display_name", "")
        if not display_name or not validate_display_name(display_name):
            return "Invalid display name", 400
            
        # Check total room limit
        if len(rooms) >= MAX_ROOMS:
            return "Maximum number of rooms reached. Please try again later.", 503
            
        # Check per-IP room limit
        hashed_ip = hash_ip(request.remote_addr)
        ip_room_count = sum(1 for room in rooms.values() if room["creator_hash"] == hashed_ip)
        if ip_room_count >= MAX_ROOMS_PER_IP:
            return "You have reached the maximum number of rooms you can create.", 403
            
        session['display_name'] = escape(display_name)
        room_id = str(uuid.uuid4())
        current_code = generate_temp_room_code()
        
        rooms[room_id] = {
            "creator_hash": hashed_ip,  # Store hashed IP instead of raw IP
            "messages": [],
            "participants": [escape(display_name)],
            "pending_requests": {},
            "created_at": time.time(),
            "current_code": current_code,
            "last_code_update": int(time.time())
        }
        return redirect(url_for("chatroom", room_code=room_id))
    return render_template("index.html")

@app.route("/room/<room_code>")
def chatroom(room_code):
    if room_code not in rooms:
        return redirect(url_for("index"))
    
    # Calculate initial time remaining
    current_time = int(time.time())
    last_update = rooms[room_code].get('last_code_update', current_time)
    time_remaining = 300 - ((current_time - last_update) % 300)
    
    return render_template(
        "chatroom.html", 
        room_code=room_code, 
        display_code=rooms[room_code]["current_code"],
        participant_count=len(rooms[room_code]["participants"]),
        initial_time=time_remaining
    )

@app.route("/join", methods=["POST"])
def join_room_route():
    input_code = request.form.get("room_code", "")
    display_name = request.form.get("display_name", "")
    
    # Add debug prints
    print(f"Attempting to join with code: {input_code}")
    print(f"Display name: {display_name}")
    
    if not display_name or not input_code:
        return "Missing room code or display name.", 400
        
    if not validate_display_name(display_name):
        return "Invalid display name format.", 400
    
    # Print all current room codes for debugging
    print("Available room codes:")
    for room_id, room_data in rooms.items():
        print(f"Room {room_id}: {room_data['current_code']}")
    
    target_room = None
    for room_id, room_data in rooms.items():
        if str(room_data["current_code"]) == str(input_code):
            target_room = room_id
            break
    
    if target_room:
        user_id = str(uuid.uuid4())
        session['user_id'] = user_id
        session['display_name'] = escape(display_name)
        session['pending_approval'] = target_room
        
        rooms[target_room]["pending_requests"][user_id] = {
            "name": escape(display_name),
            "approvals": set(),
            "timestamp": time.time()
        }
        
        socketio.emit("join_request", {
            "user": display_name,
            "user_id": user_id,
            "room": target_room
        }, room=target_room)
        
        return render_template("waiting_approval.html")
    
    return "Room not found.", 404

@socketio.on("connect")
def handle_connect():
    room_code = request.args.get("room")
    if room_code and room_code in rooms:
        join_room(room_code)
        if session.get('display_name') and session['display_name'] not in rooms[room_code]['participants']:
            rooms[room_code]['participants'].append(session['display_name'])
        
        socketio.emit('update_participants', {
            'count': len(rooms[room_code]['participants'])
        }, room=room_code)

@socketio.on('message')
def handle_message(data):
    room = data.get('room')
    message_content = data.get('message', '')
    
    # Basic validation
    if not room in rooms or not isinstance(message_content, str):
        return
    
    # Check for empty messages after trimming
    if not message_content.strip():
        return
    
    # Check message limit
    if len(rooms[room]['messages']) >= MAX_MESSAGES_PER_ROOM:
        # Remove oldest message if at limit
        rooms[room]['messages'].pop(0)
    
    message = {
        'sender': escape(session.get('display_name', 'Anonymous')),
        'content': sanitize_message(message_content),
        'timestamp': time.strftime('%H:%M:%S')
    }
    
    # Only store and emit if message isn't empty after sanitization
    if message['content']:
        rooms[room]['messages'].append(message)
        socketio.emit('message', message, room=room)

@socketio.on("request_code_update")
def handle_code_update(data):
    room_id = data["room"]
    if room_id in rooms:
        new_code = generate_temp_room_code()
        rooms[room_id]["current_code"] = new_code
        socketio.emit("code_update", {
            "code": new_code
        }, room=room_id)

@socketio.on('join')
def on_join(data):
    room = data['room']
    if room in rooms:
        join_room(room)
        # Emit updated count after joining
        socketio.emit('update_participants', {
            'count': len(rooms[room]['participants'])
        }, room=room)

@socketio.on('approve_join')
def on_approve(data):
    room = data['room']
    user_id = data['user_id']
    approver = session.get('display_name')
    
    if room in rooms and user_id in rooms[room]['pending_requests']:
        request_data = rooms[room]['pending_requests'][user_id]
        
        # Add this approver to the set of approvals
        request_data.setdefault('approvals', set()).add(approver)
        
        # Check if request has expired (1 minute)
        request_time = request_data.get('timestamp', 0)
        if time.time() - request_time > 60:
            del rooms[room]['pending_requests'][user_id]
            socketio.emit('join_denied', {
                'user_id': user_id,
                'reason': 'Request timed out'
            })
            return

        # Check if all participants have approved
        total_participants = len(rooms[room]['participants'])
        total_approvals = len(request_data['approvals'])
        
        if total_approvals == total_participants:
            # Everyone has approved - add the user
            display_name = request_data['name']
            if display_name not in rooms[room]['participants']:
                rooms[room]['participants'].append(display_name)
            del rooms[room]['pending_requests'][user_id]
            
            socketio.emit('join_approved', {
                'user_id': user_id,
                'room': room,
                'current_time': int(time.time())
            })
            
            socketio.emit('update_participants', {
                'count': len(rooms[room]['participants'])
            }, room=room)
        else:
            # Notify others about the partial approval
            socketio.emit('partial_approval', {
                'user_id': user_id,
                'approvals': total_approvals,
                'required': total_participants
            }, room=room)

@socketio.on('deny_join')
def on_deny(data):
    room = data['room']
    user_id = data['user_id']
    
    if room in rooms and user_id in rooms[room]['pending_requests']:
        del rooms[room]['pending_requests'][user_id]
        
        socketio.emit('join_denied', {
            'user_id': user_id,
            'room': room
        })

@socketio.on('disconnect')
def handle_disconnect():
    for room_id, room_data in rooms.items():
        if session.get('display_name') in room_data['participants']:
            # Remove the participant
            room_data['participants'].remove(session.get('display_name'))
            
            # Emit updated count to remaining users
            socketio.emit('update_participants', {
                'count': len(room_data['participants'])
            }, room=room_id)
            
            # If room is empty, you might want to clean it up
            if not room_data['participants']:
                rooms.pop(room_id, None)
            break

@socketio.on('request_timer_sync')
def handle_timer_sync_request(data):
    room = data.get('room')
    if room in rooms:
        current_time = int(time.time())
        last_update = rooms[room].get('last_code_update', current_time)
        time_remaining = 300 - ((current_time - last_update) % 300)
        
        socketio.emit('timer_sync', {
            'time_remaining': time_remaining
        }, room=request.sid)

@app.route("/room/<room_code>/status")
def room_status(room_code):
    if room_code not in rooms:
        return {"status": "not_found"}, 404
        
    current_time = time.time()
    room_data = rooms[room_code]
    
    return {
        "status": "active",
        "participant_count": len(room_data["participants"]),
        "message_count": len(room_data["messages"]),
        "expires_in": int(ROOM_EXPIRY_TIME - (current_time - room_data["created_at"]))
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port)