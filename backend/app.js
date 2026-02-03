const express=require("express");
const env=require("dotenv");
const {ConnectDB}=require("./schemas/userShema.js");
env.config();
const PORT=process.env.PORTenv || 3000;
const app=express();

ConnectDB();
app.use(express.json());


app.listen(PORT,()=>{
    console.log("Server is listening to port "+PORT)
})