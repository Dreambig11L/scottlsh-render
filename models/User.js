const mongoose = require("mongoose");

const UsersSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  copytrading: {
    type: String,
    
  },
  zip: {
    type: String,
    
  },
   role: {
    type: String,
    
  },
  address: {
    type: String,
    
  },
  phone: {
    type: String,
    
  },
  rank: {
    type: String,
    
  },
  state: {
    type: String,
    
  },
  server: {
    type: String,
    
  },
  city: {
    type: String,
    
  },
  mobile: {
    type: String,
    
  },
  phone: {
    type: String,
    
  },
  trader: {
    type: String,
    
  },
  condition: {
    type: String,
    
  },
  trades: {
    type: Array,
    
  },
  kyc: {
    type: String,
    
  },
  country: {
    type: String,
    
  },



  email: {
    type: String,
    required: true,
    unique: true,
  },
  referralCode:{
    type:String,
  },
  referredUsers:{
    type:Array,
  },
  planHistory:{
    type:Array,
  },
  referredBy:{
    type:String,
  },
  plan:{
    type:Array,
  },
  state:{
    type:String,
  },
 
  state:{
    type:String,
  },
 
  city: {
    type: String,
    
  },

  zip:{
    type:Object,
  },
  address:{
    type:Object,
  },
 
  password: {
    type: String,
    required: true,
    min: 6,
    max: 50,
  },
  amountDeposited: {
    type: String,
  },
  profit: {
    type: String,
  },
  balance: {
    type: String,
  },
  referalBonus: {
    type: String,
  },
  transactions: {
    type: Array,
  },
  accounts: {
    type: Object,
  },
  withdrawals: {
    type: Array,
  },
  verified: {
    type: Boolean,
  },
  isDisabled: {
    type: Boolean,
  },
});

module.exports = mongoose.model("users", UsersSchema);
