import {useState} from "react";



function Login(){
    const [name,setName]=useState("");
    const [pass,setPass]=useState("");

    function HandleSubmit(){
        
    }

    return(
        <>
        <div className="w-full h-screen">
            <div className="flex flex-col bg-red-400 h-[90%] justify-center items-center gap-2 rounded-sm">
                <h1 className="text-white">Login</h1>
                <div>
                    <input value={name} onChange={(e)=>{setName(e.target.value)}} className="h-10 rounded-md pl-2" placeholder="enter user name" />
                </div>
                <div>
                    <input value={pass} onChange={(e)=>{setPass(e.target.value)}} className="h-10 rounded-md pl-2" placeholder="enter user pass"/>
                </div>
                <div>
                    <button onClick={()=>{HandleSubmit}} className="btn btn-accent btn-sm">Submit</button>
                </div>
            </div>
        </div>
        </>
    )
}

export default Login;