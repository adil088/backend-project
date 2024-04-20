import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"

const registerUser = asyncHandler(async (req, res) => {
  // get user details from front end


  const { fullname, email, username, password } = req.body;
  console.log("Email", email, password);

    //validation - not empty
  if (
    [fullname, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

      //check if user already exists
  const existerUser = await User.findOne({
    $or: [{ username }, { email }],
  });


  if (existerUser) {
    throw new ApiError(409, "User with email or username already exists");
  }
  //check for images and check for avatar
  const avatarLocalPath = req.files?.avatar[0]?.path;
  //const coverImageLocalPath = req.files?.coverImage[0]?.path;
  
  //check for coverImage
  let coverImageLocalPath;
  if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0 ) {
    coverImageLocalPath = req.files.coverImage[0].path
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required")
  }

  //Upload them to cloudinary, avatar

  const avatar = await uploadOnCloudinary(avatarLocalPath)
  const coverImage = await uploadOnCloudinary(coverImageLocalPath)

  if(!avatar){
    throw new ApiError(400, "Avatar file is required")
  }

  //Create user object, create entry in DB
  const user = await User.create({
    fullname,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",  // if exists ? else empty string
    email,
    password,
    username: username.toLowerCase()
  })

  //remove password and refresh token field
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  )

  if(!createdUser){
    throw new ApiError(500, "Something went wrong while registering the user")
  }

  // Return response
  return res.status(201).json(
    new ApiResponse(200, createdUser, "User registered successfully")
  )

});

export { registerUser };
