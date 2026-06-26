const express = require("express");
const http = require("http");
const { Server: SocketIOServer } = require("socket.io");
const path = require("path");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const { randomBytes } = require("crypto");
//const { uploadFile } = require("./upload.js");
const multer = require("multer");
const fs = require("fs");
const uploadMeta = new Map(); // id -> { originalName, mime }
const { v4: uuidv4 } = require("uuid");
const session = require("express-session");

// Load environment variables from .env file
dotenv.config({ path: "./config.env" });

const app = express();
const server = http.createServer(app);
//const io = new SocketIOServer(server);
const io = new SocketIOServer(server, {
  transports: ["websocket"],
  connectTimeout: 5000,
});


const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";
const SESSION_SECRET = process.env.SESSION_SECRET || "your_session_secret";
const MAX_ROOM_ID_LENGTH = 20;
const ROOM_ID_REGEX = /^[A-Za-z0-9-_@#$]+$/;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

//added for local upload
const UPLOAD_DIR = path.join(__dirname, "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

app.use("/uploads", express.static(UPLOAD_DIR));



// Middleware to parse JSON bodies
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, "public")));

// Route for the main page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Route for room pages
app.get("/room/:id", (req, res) => {
  const roomId = req.params.id;
  if (roomId.length > MAX_ROOM_ID_LENGTH) {
    return res
      .status(400)
      .send(
        `Room ID exceeds the maximum length of ${MAX_ROOM_ID_LENGTH} characters`
      );
  }
  if (!ROOM_ID_REGEX.test(roomId)) {
    return res
      .status(400)
      .send(
        "Invalid room ID format. Only alphanumeric characters (A-Z, a-z, 0-9) and special characters (-, _, @, #, $) are allowed"
      );
  }
  res.sendFile(path.join(__dirname, "public", "room.html"));
});

// Store active users with their tokens
const activeUsers = new Map();

// Route to generate JWT token for a user
app.post("/login", async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }
  if (
    Array.from(activeUsers.values()).some((user) => user.username === username)
  ) {
    return res.status(400).json({ error: "Username already exists" });
  }

  const userId = uuidv4();
  const hashedUsername = await bcrypt.hash(username, 10);
  const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: "3h" });
  activeUsers.set(userId, { username, hashedUsername, token });
  req.session.userId = userId; // Store the user ID in session
  res.json({ token, userId });
});

//for local upload
app.post("/upload", upload.single("file"), (req, res) => {
  const id = req.file.filename; // multer-generated id in uploads folder
  uploadMeta.set(id, {
    originalName: req.file.originalname,
    mime: req.file.mimetype,
  });

  res.json({
    url: `/uploads/${id}`,                 // view/open
    downloadUrl: `/download/${id}`,        // download with correct name
    originalName: req.file.originalname,
    mime: req.file.mimetype,
    size: req.file.size,
  });
});


// New route to generate a random 64-bit token
app.get("/generate", (req, res) => {
  const token = randomBytes(64).toString("hex");
  res.send(token);
});

// Middleware to verify JWT token for socket connections
async function verifyJWT(socket, next) {
  const token = socket.handshake.auth.token;
  if (token) {
    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) return next(new Error("Authentication error"));

      const { userId, username } = decoded;
      const user = activeUsers.get(userId);

      if (
        !user ||
        user.username !== username ||
        !(await bcrypt.compare(username, user.hashedUsername)) ||
        user.token !== token
      ) {
        return next(new Error("Authentication error"));
      }

      socket.userId = userId;
      socket.username = username;
      socket.token = token; // Save token in socket
      next();
    });
  } else {
    next(new Error("Authentication error"));
  }
}


// added for filename + extention forcing 
app.get("/download/:id", (req, res) => {
  const id = req.params.id;
  const meta = uploadMeta.get(id);

  // If server restarted, meta might be missing; fallback to id
  const downloadName = meta?.originalName || id;

  const filePath = path.join(UPLOAD_DIR, id);
  res.download(filePath, downloadName);
});


// Set up socket.io events with JWT authentication
io.use(verifyJWT).on("connection", (socket) => {
  console.log("a user connected");
  socket.emit("user_name", { username: socket.username });

  // Event handler for joining a room
  socket.on("joinRoom", (room) => {
    if (room.length > MAX_ROOM_ID_LENGTH) {
      socket.emit(
        "errorMessage",
        `Room ID exceeds the maximum length of ${MAX_ROOM_ID_LENGTH} characters`
      );
      return;
    }
    if (!ROOM_ID_REGEX.test(room)) {
      socket.emit(
        "errorMessage",
        "Invalid room ID format. Only alphanumeric characters (A-Z, a-z, 0-9) and special characters (-, _, @, #, $) are allowed"
      );
      return;
    }
    socket.join(room);
    console.log(`User ${socket.username} joined room: ${room}`);
    socket.broadcast.to(room).emit("userJoined", { username: socket.username });

    const onlineUsers = Array.from(
      io.sockets.adapter.rooms.get(room) || []
    ).map((socketId) => io.sockets.sockets.get(socketId).username);

    io.to(room).emit("botMessage", {
      username: "ChatBot",
      message: `Welcome ${socket.username}!<br />There are ${onlineUsers.length} users online.<br />Your username is ${socket.username} and you are in room ${room}.`,
    });
  });

  // Event handler for receiving chat messages
  socket.on("chatMessage", (msg) => {
    io.to(msg.room).emit("chatMessage", {
      username: socket.username,
      message: msg.message,
    });
  });

  // Event handler for file uploads
  // socket.on("uploadFile", async (file) => {
  //   try {
  //     const { base64Data, fileName, contentType } = file;
  //     const url = await uploadFile(base64Data, fileName, contentType);
  //     io.to(file.room).emit("fileUploaded", {
  //       username: socket.username,
  //       file: { url, fileName },
  //     });
  //   } catch (error) {
  //     console.error("Error uploading file:", error);
  //     socket.emit("uploadError", "File upload failed. Please try again.");
  //   }
  // });

  // Event handler for user disconnection
  socket.on("disconnect", () => {
    console.log(`User ${socket.username} disconnected`);
    socket.broadcast.emit("userDisconnect", { username: socket.username });

    // Check if the user is still active
    const user = activeUsers.get(socket.userId);
    if (user && user.token !== socket.token) {
      activeUsers.delete(socket.userId);
    }
  });
});

// Start the server
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
