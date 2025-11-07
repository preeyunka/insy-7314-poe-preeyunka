const { DataTypes } = require('sequelize');
const sequelize = require('../sequelize'); 

const LoanApplication = sequelize.define('LoanApplication', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, allowNull: false },
    amount: { type: DataTypes.FLOAT, allowNull: false },
    payslipPath: { type: DataTypes.STRING, allowNull: true },
    status: { type: DataTypes.STRING, allowNull: false, defaultValue: 'Pending' }
}, { tableName: 'LoanApplications' });

module.exports = LoanApplication;

