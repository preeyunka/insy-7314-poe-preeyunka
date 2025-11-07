const sequelize = require("./sequelize");
const Employee = require("./models/Employee");
const bcrypt = require("bcrypt");

(async () => {
    await sequelize.sync();

    const email = "employee@globepay.com";
    const password = "Admin123!";
    const hash = await bcrypt.hash(password, 12);

    await Employee.create({
        email,
        passwordHash: hash,
        role: "employee",
    });

    console.log("Employee created in SQLite!");
    process.exit();
})();

