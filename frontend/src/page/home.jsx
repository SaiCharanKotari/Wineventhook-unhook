import Login from "../components/login.jsx"


function Home(){
    return(
        <>
        <div className="bg-slate-600 w-screen h-screen overflow-hidden">
            <div className="grid h-full grid-rows-[10%,90%]">
                <div className="bg-black flex justify-center items-center">
                    <h1 className="text-white font-bold text-3xl">Notes table</h1>
                </div>
                <div>
                    <div className="grid grid-cols-[30%,70%]">
                        <Login />
                        <div>
                            <div className="grid grid-rows-[25%,75%] h-full">
                                <input className="border-4 rounded-lg" placeholder="Subject" />
                                <input className="border-4 rounded-lg" placeholder="matter!"/>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        </>
    )
}
export default Home;