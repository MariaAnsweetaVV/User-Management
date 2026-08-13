require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const cookieParser = require("cookie-parser");

const { connectDB, collection } = require("./config");

const app = express();

// MIDDLEWARE

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true
    }
  })
);

// VIEW ENGINE

app.set("view engine", "ejs");

app.use(express.static("public"));

// HOME / ROOT

app.get("/", (req, res) => {

  if (!req.session.user) {
    return res.redirect("/login");
  }

  if (req.session.role === "admin") {
    return res.redirect("/admin");
  }

  if (req.session.role === "subadmin") {
    return res.redirect("/subadmin");
  }

  if (req.session.role === "user") {
    return res.redirect("/home");
  }

  return res.redirect("/login");
});

// LOGIN PAGE

app.get("/login", (req, res) => {

  if (req.session.user) {
    return res.redirect("/");
  }

  res.render("login", {
    error: ""
  });
});

// SIGNUP PAGE

app.get("/signup", (req, res) => {

  if (req.session.user) {
    return res.redirect("/");
  }

  res.render("signup", {
    error: ""
  });

});

// NORMAL USER SIGNUP

app.post("/signup", async (req, res) => {

  try {

    const {
      username,
      password
    } = req.body;

    // Check existing user

    const existingUser = await collection.findOne({
      name: username
    });


    if (existingUser) {
      return res.render("signup", {
        error: "User already exists. Please choose another username"
      });
    }
    // Hash password

    const hashedPassword = await bcrypt.hash(
      password,
      10
    );

    // Create normal user

    await collection.create({

      name: username,

      password: hashedPassword,

      role: "user",

      permissions: {

        createUser: false,

        editUser: false,

        deleteUser: false,

        viewUser: true

      }

    });


    console.log(
      "User created successfully"
    );


    res.redirect("/login");


  } catch (error) {

    console.log(error);

    return res.render("signup", {
      error: "Signup failed"
    });

  }

});

// LOGIN

app.post("/login", async (req, res) => {

  try {

    const {
      username,
      password
    } = req.body;


    // Find user

    const user = await collection.findOne({
      name: username
    });


    if (!user) {
      return res.render("login", {
        error: "credentials invalid"
      });
    }

    // Compare password

    const passwordMatch = await bcrypt.compare(
      password,
      user.password
    );


    if (!passwordMatch) {
      return res.render("login", {
        error: "credentials invalid"
      });
    }

    // SAVE USER IN SESSION

    req.session.user = user.name;

    req.session.role = user.role;

    req.session.userId = user._id.toString();

    // REDIRECT BASED ON ROLE

    if (user.role === "admin") {

      return res.redirect("/admin");

    }


    if (user.role === "subadmin") {

      return res.redirect("/subadmin");

    }


    return res.redirect("/home");


  } catch (error) {

    console.log(error);

    return res.render("login", {
      error: "Login failed"
    });

  }

});

// NORMAL USER HOME

app.get("/home", (req, res) => {

  if (!req.session.user) {

    return res.redirect("/login");

  }

  // Only normal users

  if (req.session.role !== "user") {

    return res.redirect("/");

  }


  res.set(
    "Cache-Control",
    "no-store"
  );


  res.render("home", {

    username: req.session.user

  });

});

// ADMIN MIDDLEWARE

function isAdmin(req, res, next) {

  if (!req.session.user) {

    return res.redirect("/login");

  }


  if (req.session.role !== "admin") {

    return res.status(403).render("login", {
      error: "Access Denied"
    });

  }


  next();

}

// SUBADMIN MIDDLEWARE

function isSubadmin(req, res, next) {

  if (!req.session.user) {

    return res.redirect("/login");

  }


  if (req.session.role !== "subadmin") {

    return res.status(403).render("login", {
      error: "Access Denied"
    });

  }


  next();

}

// PERMISSION MIDDLEWARE

function checkPermission(permission) {

  return async (req, res, next) => {

    try {

      const user = await collection.findById(
        req.session.userId
      );


      if (!user) {

        return res.redirect(
          "/login"
        );

      }

      // Admin has all permissions

      if (user.role === "admin") {

        return next();

      }

      // Check permission

      if (
        !user.permissions ||
        !user.permissions[permission]
      ) {

        return res.status(403).render("login", {
          error:
            "You do not have permission to perform this action"
        });

      }


      next();


    } catch (error) {

      console.log(error);

      return res.status(500).render("login", {
        error: "Permission check failed"
      });

    }

  };

}

// ADMIN DASHBOARD

app.get(
  "/admin",
  isAdmin,
  async (req, res) => {

    try {

      const users =
        await collection.find().lean();


      res.render(
        "admin-dashboard",
        {

          username: req.session.user,

          users: users,

          error: ""

        }
      );


    } catch (error) {

      console.log(error);

      return res.status(500).render(
        "admin-dashboard",
        {
          username: req.session.user,
          users: [],
          error: "Unable to load admin dashboard"
        }
      );

    }

  }
);

// ADMIN - ADD USER PAGE

app.get(
  "/admin/add-user",
  isAdmin,
  (req, res) => {

    res.render("add-user", {
      error: ""
    });

  }
);

// ADMIN - ADD USER / SUBADMIN

app.post(
  "/admin/add-user",
  isAdmin,
  async (req, res) => {

    try {

      const {
        username,
        password,
        role
      } = req.body;

      // Check fields

      if (
        !username ||
        !password ||
        !role
      ) {

        return res.render("add-user", {
          error: "All fields are required"
        });

      }

      // Only user and subadmin allowed

      if (
        !["user", "subadmin"].includes(role)
      ) {

        return res.status(400).render(
          "add-user",
          {
            error: "Invalid role"
          }
        );

      }


      // Check existing username

      const existingUser =
        await collection.findOne({
          name: username
        });


      if (existingUser) {

        return res.render("add-user", {
          error: "Username already exists"
        });

      }


      // Hash password

      const hashedPassword =
        await bcrypt.hash(
          password,
          10
        );

      // DEFAULT USER PERMISSIONS

      let permissions = {

        createUser: false,

        editUser: false,

        deleteUser: false,

        viewUser: true

      };

      // SUBADMIN PERMISSIONS

      if (role === "subadmin") {

        permissions = {

          createUser: true,

          editUser: true,

          deleteUser: false,

          viewUser: true

        };

      }

      // CREATE USER

      await collection.create({

        name: username,

        password: hashedPassword,

        role: role,

        permissions: permissions

      });


      console.log(
        `${role} created successfully`
      );


      res.redirect("/admin");


    } catch (error) {

      console.log(error);

      return res.render("add-user", {
        error: "Failed to create user"
      });

    }

  }
);

// ADMIN - EDIT USER PAGE

app.get(
  "/admin/edit/:id",
  isAdmin,
  async (req, res) => {

    try {

      const user =
        await collection.findById(
          req.params.id
        );


      if (!user) {
        return res.render(
          "admin-dashboard",
          {
            username: req.session.user,
            users: [],
            error: "User not found"
          }
        );

      }


      // Admin cannot be edited

      if (user.role === "admin") {

        return res.render(
          "admin-dashboard",
          {
            username: req.session.user,
            users: [],
            error: "Admin account cannot be edited"
          }
        );

      }


      res.render(
        "edit-user",
        {
          user: user,
          error: ""
        }
      );


    } catch (error) {

      console.log(error);

      return res.render(
        "admin-dashboard",
        {
          username: req.session.user,
          users: [],
          error: "Unable to load user"
        }
      );

    }

  }
);

// ADMIN - UPDATE USER

app.post(
  "/admin/edit/:id",
  isAdmin,
  async (req, res) => {

    try {

      const {
        username,
        role
      } = req.body;


      if (!username || !role) {

        return res.render(
          "edit-user",
          {
            user: user,
            error: "Username and role are required"
          }
        );

      }


      if (
        !["user", "subadmin"].includes(role)
      ) {

        return res.status(400).render(
          "edit-user",
          {
            user: user,
            error: "Invalid role"
          }
        );

      }


      const user =
        await collection.findById(
          req.params.id
        );


      if (!user) {

        return res.render(
          "admin-dashboard",
          {
            username: req.session.user,
            users: [],
            error: "User not found"
          }
        );

      }

      // Admin cannot be edited

      if (user.role === "admin") {

        return res.render(
          "edit-user",
          {
            user: user,
            error: "Admin account cannot be edited"
          }
        );

      }

      // Check duplicate username

      const existingUser =
        await collection.findOne({

          name: username,

          _id: {
            $ne: user._id
          }

        });


      if (existingUser) {

        return res.render(
          "edit-user",
          {
            user: user,
            error: "Username already exists"
          }
        );

      }

      // DEFAULT USER PERMISSIONS

      let permissions = {

        createUser: false,

        editUser: false,

        deleteUser: false,

        viewUser: true

      };

      // SUBADMIN DEFAULT PERMISSIONS

      if (role === "subadmin") {

        permissions = {

          createUser: true,

          editUser: true,

          deleteUser: false,

          viewUser: true

        };

      }

      // UPDATE USER

      await collection.findByIdAndUpdate(

        req.params.id,

        {

          name: username,

          role: role,

          permissions: permissions

        }

      );


      console.log(
        "User updated successfully"
      );


      res.redirect("/admin");


    } catch (error) {

      console.log(error);

      return res.render(
        "edit-user",
        {
          user: null,
          error: "Failed to update user"
        }
      );

    }

  }
);

// ADMIN - DELETE USER

app.post(
  "/admin/delete/:id",
  isAdmin,
  async (req, res) => {

    try {

      const user =
        await collection.findById(
          req.params.id
        );


      if (!user) {

        return res.render(
          "admin-dashboard",
          {
            username: req.session.user,
            users: [],
            error: "User not found"
          }
        );

      }

      // Protect Admin

      if (user.role === "admin") {

        return res.status(403).render(
          "admin-dashboard",
          {
            username: req.session.user,
            users: [],
            error: "Admin account cannot be deleted"
          }
        );
      }


      await collection.findByIdAndDelete(
        req.params.id
      );


      console.log(
        `User ${user.name} deleted successfully`
      );


      res.redirect("/admin");


    } catch (error) {

      console.log(error);

      return res.render(
        "admin-dashboard",
        {
          username: req.session.user,
          users: [],
          error: "Failed to delete user"
        }
      );

    }

  }
);

// ADMIN - SUBADMIN PERMISSION PAGE

app.get(
  "/admin/permissions/:id",
  isAdmin,
  async (req, res) => {

    try {

      const user =
        await collection.findById(
          req.params.id
        );


      if (!user) {

        return res.render(
          "admin-dashboard",
          {
            username: req.session.user,
            users: [],
            error: "User not found"
          }
        );

      }

      // Only Subadmin permissions can be changed

      if (user.role !== "subadmin") {

        return res.status(403).render(
          "admin-dashboard",
          {
            username: req.session.user,
            users: [],
            error:
              "Permissions can only be changed for subadmins"
          }
        );

      }


      res.render(
        "admin-permissions",
        {
          user: user,
          error: ""
        }
      );


    } catch (error) {

      console.log(error);

      return res.render(
        "admin-dashboard",
        {
          username: req.session.user,
          users: [],
          error: "Unable to load permissions"
        }
      );

    }

  }
);

// ADMIN - UPDATE SUBADMIN PERMISSIONS

app.post(
  "/admin/permissions/:id",
  isAdmin,
  async (req, res) => {

    try {

      const {
        viewUser,
        createUser,
        editUser,
        deleteUser
      } = req.body;


      // Find Subadmin

      const user =
        await collection.findById(
          req.params.id
        );


      if (!user) {

        return res.render(
          "admin-dashboard",
          {
            username: req.session.user,
            users: [],
            error: "User not found"
          }
        );

      }


      // Only Subadmin

      if (user.role !== "subadmin") {

        return res.status(403).render(
          "admin-dashboard",
          {
            username: req.session.user,
            users: [],
            error:
              "Permissions can be managed only for subadmin"
          }
        );

      }

      // SAVE PERMISSIONS

      await collection.findByIdAndUpdate(

        req.params.id,

        {

          permissions: {

            viewUser: viewUser === "on",

            createUser: createUser === "on",

            editUser: editUser === "on",

            deleteUser: deleteUser === "on"

          }

        }

      );


      console.log(
        `Permissions updated for ${user.name}`
      );


      res.redirect("/admin");


    } catch (error) {

      console.log(error);

      return res.render(
        "admin-permissions",
        {
          user: null,
          error: "Failed to update permissions"
        }
      );

    }

  }
);

// SUBADMIN DASHBOARD

app.get(
  "/subadmin",
  isSubadmin,
  checkPermission("viewUser"),
  async (req, res) => {
    try {
      const users =
        await collection.find({
          role: "user"
        }).lean();
      res.render(
        "subadmin-dashboard",
        {
          username: req.session.user,
          users: users,
          error: ""
        }
      );
    } catch (error) {
      console.log(error);
      return res.status(500).render(
        "subadmin-dashboard",
        {
          username: req.session.user,
          users: [],
          error: "Unable to load user"
        }
      );
    }
  }
);

// SUBADMIN - ADD USER

app.post(
  "/subadmin/add-user",
  isSubadmin,
  checkPermission("createUser"),
  async (req, res) => {

    try {
      const {
        username,
        password
      } = req.body;
      if (!username || !password) {
        return res.render(
          "subadmin-dashboard",
          {
            username: req.session.user,
            users: [],
            error:
              "Username and password are required"
          }
        );
      }

      // Check existing username

      const existingUser =
        await collection.findOne({
          name: username
        });
      if (existingUser) {
        return res.render(
          "subadmin-dashboard",
          {
            username: req.session.user,
            users: [],
            error: "Username already exists"
          }
        );
      }

      // Hash password

      const hashedPassword =
        await bcrypt.hash(
          password,
          10
        );

      // Create only normal user

      await collection.create({
        name: username,
        password: hashedPassword,
        role: "user",
        permissions: {
          createUser: false,
          editUser: false,
          deleteUser: false,
          viewUser: true
        }
      });
      console.log(
        `User ${username} created by subadmin`
      );
      res.redirect("/subadmin");
    } catch (error) {
      console.log(error);

      return res.render(
        "subadmin-dashboard",
        {
          username: req.session.user,
          users: [],
          error: "Failed to create user"
        }
      );
    }
  }
);

// SUBADMIN - EDIT USER PAGE

app.get(
  "/subadmin/edit/:id",
  isSubadmin,
  checkPermission("editUser"),
  async (req, res) => {
    try {
      const user =
        await collection.findById(
          req.params.id
        );
      if (!user) {
        return res.render(
          "subadmin-dashboard",
          {
            username: req.session.user,
            users: [],
            error: "User not found"
          }
        );
      }

      // Subadmin can edit only normal users

      if (user.role !== "user") {
        return res.status(403).render(
          "subadmin-dashboard",
          {
            username: req.session.user,
            users: [],
            error:
              "Subadmin can edit only normal users"
          }
        );
      }
      res.render(
        "subadmin-edit-user",
        {
          user: user,
          error: ""
        }
      );
    } catch (error) {
      console.log(error);

      return res.render(
        "subadmin-dashboard",
        {
          username: req.session.user,
          users: [],
          error: "Unable to load user"
        }
      );
    }
  }
);

// SUBADMIN - UPDATE USER

app.post(
  "/subadmin/edit/:id",
  isSubadmin,
  checkPermission("editUser"),
  async (req, res) => {

    try {
      const {
        username
      } = req.body;
      if (!username) {
        return res.render(
          "subadmin-edit-user",
          {
            user: user,
            error: "Username is required"
          }
        );
      }

      if (!user) {
        return res.render(
          "subadmin-dashboard",
          {
            username: req.session.user,
            users: [],
            error: "User not found"
          }
        );
      }

      // Protect Admin and Subadmin

      if (user.role !== "user") {
        return res.status(403).render(
          "subadmin-edit-user",
          {
            user: user,
            error:
              "Subadmin can edit only normal users"
          }
        );
      }

      // Check duplicate username

      const existingUser =
        await collection.findOne({
          name: username,
          _id: {
            $ne: user._id
          }
        });

      if (existingUser) {
        return res.render(
          "subadmin-edit-user",
          {
            user: user,
            error: "Username already exists"
          }
        );
      }

      // Update user

      await collection.findByIdAndUpdate(
        req.params.id,
        {
          name: username
        }
      );
      console.log(
        `User ${username} updated by subadmin`
      );
      res.redirect("/subadmin");
    } catch (error) {
      console.log(error);

      return res.render(
        "subadmin-edit-user",
        {
          user: null,
          error: "Failed to update user"
        }
      );
    }
  }
);

// LOGOUT

app.post(
  "/logout",
  (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        return res.render("login", {
          error: "Logout failed"
        });
      }
      res.clearCookie(
        "connect.sid"
      );
      res.redirect("/login");
    });
  }
);

// START SERVER

async function startServer() {

  try {
    await connectDB();
    app.listen(
      1000,
      () => {
        console.log(
          "Server running on http://localhost:1000"
        );
      }
    );

  } catch (error) {
    console.log(
      "Server failed to start"
    );
    console.log(error);
  }
}

startServer();