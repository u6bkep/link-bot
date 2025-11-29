FROM python:3.11

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install dependencies
RUN --mount=type=cache,target=/var/cache/apt --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt 
    
# build slice
ARG SLICE_NAME="MumbleServer_v1_5_735.ice"
COPY slices/${SLICE_NAME} .
# build slice
RUN slice2py ${SLICE_NAME}

# Copy the application code
COPY link-bot.py .
COPY links-config.json .

# define volume for configuration
VOLUME /app/links-config.json

# set environment variables
ENV MUMBLE_ICE_HOST=mumble-server
ENV MUMBLE_ICE_PORT=6502
ENV MUMBLE_ICE_SECRET=""
ENV ICE_CALLBACK_HOST=link-bot
ENV ICE_CALLBACK_PORT=6503
ENV LINK_BOT_CONFIG=/app/links-config.json
ENV LINK_BOT_LOG_LEVEL=INFO
ENV LINK_BOT_MAX_MESSAGE_LENGTH=5000

CMD ["python", "link-bot.py"]