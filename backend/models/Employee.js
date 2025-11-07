const { Sequelize, DataTypes } = require("sequelize");
const sequelize = require("../sequelize");

const Employee = sequelize.define(
    "Employee",
    {
        email: { type: DataTypes.STRING, unique: true, allowNull: false },
        passwordHash: { type: DataTypes.STRING, allowNull: false },
        role: { type: DataTypes.STRING, defaultValue: "employee" }
    },
    { tableName: "Employees" }
);

module.exports = Employee;

