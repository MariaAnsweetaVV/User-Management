const bcrypt = require("bcrypt");

const { connectDB, collection } = require("./config");

async function createAdmin() {
  try {

    // Wait for database connection
    await connectDB();

    // Check if admin already exists
    const existingAdmin = await collection.findOne({
      role: "admin"
    });

    if (existingAdmin) {
      console.log("Admin already exists");
      process.exit(0);
    }

    // Hash admin password
    const hashedPassword = await bcrypt.hash("admin123", 10);

    // Create admin
    await collection.create({
      name: "admin",
      password: hashedPassword,
      role: "admin",

      permissions: {
        createUser: true,
        editUser: true,
        deleteUser: true,
        viewUser: true
      }
    });

    console.log("Admin created successfully");
    console.log("Username: admin");
    console.log("Password: admin123");

    process.exit(0);

  } catch (error) {

    console.log("Error creating admin:");
    console.log(error);

    process.exit(1);
  }
}

createAdmin();