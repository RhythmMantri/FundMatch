const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/fundmatch');

const userSchema = new mongoose.Schema({
  fullname: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  company: {
    type: String,
    trim: true
  },
  bio: {
    type: String,
    default: ''
  },
  role: {
    type: String,
    enum: ['startup', 'investor'],
    default: 'startup'
  },
  profileComplete: {
    type: Number,
    default: 20 // Basic profile with just registration info is 20% complete
  },
  profileImage: {
    type: String,
    default: ''
  },
  coverImage: {
    type: String,
    default: ''
  },
  companyDetails: {
    industry: String,
    description: String,
    founded: Date,
    location: String,
    teamSize: String
  },
  socialLinks: {
    website: String,
    linkedin: String,
    twitter: String
  },
  fundingInfo: {
    seeking: Number,
    stage: String,
    raised: Number,
    valuation: Number
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Pre-save middleware to update the updatedAt field
userSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('User', userSchema);