const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const userSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    resetPasswordToken: {
      type: String,
    },
    resetPasswordExpire: {
      type: String,
    },
    lastLoginIP: {
      type: String,
      default: null
    },
    lastLoginDevice: {
      type: String,
      default: null
    },
    securityLevel: {
      type: String,
      enum: ["low", "medium", "high"],
      default: "low"
    },
    avatar: {
      type: String,
    },
    followers: [
      {
        type: Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    following: [
      {
        type: Schema.Types.ObjectId,
        ref: "User",
      },
    ],

    location: {
      type: String,
      default: "",
    },

    bio: {
      type: String,
      default: "",
    },

    interests: {
      type: String,
      default: "",
    },

    role: {
      type: String,
      enum: ["general", "moderator", "admin"],
      default: "general",
    },

    savedPosts: [
      {
        type: Schema.Types.ObjectId,
        ref: "Post",
        default: [],
      },
    ],

    isEmailVerified: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.index({ name: "text" });
module.exports = mongoose.model("User", userSchema);
