# Secure Chat Room Application

A real-time secure chat application built with Flask and Socket.IO, featuring temporary room codes, end-to-end encryption, and user approval system.

## Features

- **Temporary Room Codes**: Dynamic 6-digit room codes that refresh every 5 minutes
- **End-to-End Encryption**: Client-side message encryption
- **User Approval System**: New users must be approved by existing room members
- **Auto-Expiring Rooms**: Rooms automatically expire after 24 hours
- **Participant Management**: Real-time participant tracking and notifications
- **System Messages**: Join/leave notifications and other system updates
- **Modern UI**: iMessage-inspired interface with animations
- **Security Features**: CSRF protection, input sanitization, and rate limiting

## Prerequisites

- Python 3.7+
- Flask
- Socket.IO
- Additional dependencies listed in requirements.txt

## Installation

1. Clone the repository:
```bash
git clone https://github.com/rolextital/Encrypted-Chat-Room.git
cd secure-chat
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory:
```
FLASK_SECRET_KEY=your_secret_key_here
```

## Running the Application

### Development Server
```bash
python main.py
```

### Production Server (using Gunicorn)
```bash
gunicorn -k eventlet -w 1 main:app
```

The application will be available at `https://encrypted-chat-room.onrender.com`

## Usage

1. **Creating a Room**:
   - Enter your display name
   - Click "Create Chat"
   - Share the 6-digit room code with others

2. **Joining a Room**:
   - Enter your display name
   - Input the 6-digit room code
   - Wait for approval from existing room members

3. **Chat Features**:
   - Real-time messaging
   - Participant count updates
   - Room code refresh countdown
   - Join/leave notifications

## Security Features

- Message encryption using CryptoJS
- CSRF protection
- Input sanitization
- Rate limiting
- Room participant limits
- Message length restrictions
- Automatic room expiration
- Secure WebSocket connections

## File Structure

```
secure-chat/
├── main.py
├── templates/
│   ├── index.html
│   ├── chatroom.html
│   └── waiting_approval.html
├── static/
│   └── styles.css
├── gunicorn_config.py
└── .env
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Flask framework
- Socket.IO
- CryptoJS
- Modern web technologies

## Support

For support, please open an issue in the repository or contact the maintainers.
