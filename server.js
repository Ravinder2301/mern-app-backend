// Import necessary modules
import express from "express"; // Express.js framework
import mongoose from "mongoose";
import cors from "cors"; // Cross-Origin Resource Sharing middleware
import jwt from "jsonwebtoken"; // JSON Web Token implementation
import bcrypt from "bcryptjs"; // Password hashing library
import cookieParser from "cookie-parser"; // Parse cookies
import dotenv from "dotenv"; // Load environment variables from a .env file
import { User } from "./DBSchema/schema.js";
dotenv.config(); // Initialize dotenv

// Initialize Express app
const app = express();
const URL = process.env.MONGO_URL;

// Middleware
app.use(express.json()); // Parse JSON bodies
// Middleware
app.use(
  cors({
    origin: "https://frolicking-puppy-f5f76c.netlify.app/", // Allow requests from this origin
    methods: ["POST", "GET"], // Allow specified HTTP methods
    credentials: true, // Allow sending cookies
  })
);

// Middleware
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

app.use(cookieParser()); // Parse cookies

// Database connection
mongoose
  .connect(URL)
  .then(() => {
    console.log("App connected to database");
  })
  .catch((err) => {
    console.log(err);
  });

// Middleware to verify user authentication
const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Error: "You are not authenticated" });
  } else {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.json({ Error: "token is not correct" });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
};

// Route: Home page (requires authentication)
app.get("/", verifyUser, (req, res) => {
  return res.json({ Status: "Success", name: req.name });
});

// Route: User registration
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if all required fields are provided
    if (!name || !email || !password) {
      return res.json({ Error: "Send all required fields!" });
    }

    // Check if email already exists in the database
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.json({ Error: "Email already exists!" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
    });
    //   await newUser.save();

    return res.json({ Status: "Success" });
  } catch (err) {
    console.log(err);
    return res.json({ Error: "Registration error in server" });
  }
});

// Route: User login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
      return res.json({ Error: "Send all required fields!" });
    }

    // Check if user with provided email exists in the database
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ Error: "No user with that email exists" });
    }

    // Compare passwords
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (passwordMatch) {
      // Generate JWT token
      const token = jwt.sign({ name: user.name }, process.env.JWT_SECRET, {
        expiresIn: "1d",
      });
      // Set token in cookie
      res.cookie('token', token, {
        httpOnly: true,
        secure: true,
        sameSite: "none"
      }
      );

      return res.json({ Status: "Success" });
    } else {
      return res.json({ Error: "Password incorrect" });
    }
  } catch (err) {
    console.log(err);
    return res.json({ Error: "Login error in server" });
  }
});

// Route: User logout
app.get("/logout", (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: true,
      sameSite: "none"
    }); // Clear JWT token from cookie
    return res.json({ Status: "Success" });
  } catch (err) {
    console.log(err);
    return res.json({ Error: "Logout error in server" });
  }
});

// Start the server
app.listen(process.env.PORT, () => {
  console.log(`Port running on : ${process.env.PORT} `);
});
