const mongoose=require("mongoose");


const ConnectDB = async()=> {
    try{
        await mongoose.connect(process.env.MONGO_URL);
        console.log("MongoDB connected");
    }catch(error){
        console.log("Unsuccessfull Mongodb connection");
        console.log(error);
        process.exit(1);
    }
};

const userSchema= new mongoose.Schema(
    {
        username:{
            type:String,
            required:true,
            unique:true,
            trim:true
        },
        password:{
            type:String,
            required:true,
        }
        
    },
    { timestamps: true }
)

const user=mongoose.model("User",userSchema);

module.exports={ConnectDB,user};