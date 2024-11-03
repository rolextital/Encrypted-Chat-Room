import os

worker_class = 'geventwebsocket.gunicorn.workers.GeventWebSocketWorker'
workers = 1
bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"