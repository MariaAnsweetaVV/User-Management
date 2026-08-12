const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Database connected Successfully");
  } catch (error) {
    console.log("Database cannot be connected");
    throw error;
  }
};

const LoginSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },

  password: {
    type: String,
    required: true
  },

  role: {
    type: String,
    enum: ["user", "admin", "subadmin"],
    default: "user"
  },

  permissions: {
    createUser: {
      type: Boolean,
      default: false
    },

    editUser: {
      type: Boolean,
      default: false
    },

    deleteUser: {
      type: Boolean,
      default: false
    },

    viewUser: {
      type: Boolean,
      default: true
    }
  }
});

const collection = mongoose.model("users", LoginSchema);

module.exports = {
  connectDB,
  collection
};