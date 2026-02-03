const {user} =require("../schemas/userShema");

const registerUser=async(req,res)=>{
    try{
        const {username,password}=req.body;
        const  newUser=await user.create({
            username,
            password
        });
        res.status(201).json(newUser);
    }catch(error){
        res.status(500).json({message:"Failed"});
    }
}
module.exports=registerUser;