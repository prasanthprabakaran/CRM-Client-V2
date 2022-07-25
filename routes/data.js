import express, { response } from 'express';
// import User from '../models/User';
import { client } from "../index.js";
const router = express.Router();


// const registerData= (req, res) => {
//     response.json({ message: "data"});
// }

// router.get("/", registerData);

//find all
router.get("/",async function (request, response) {

    const list = await client
    .db("client")
    .collection("data")
    .find(request.query)
    .toArray();
    response.send(list);
});


router.post("/",async function (request, response) {
    const data = request.body;
    console.log(data);
    // db.list.insertMany(data)

    const result = await client
    .db("client")
    .collection("data")
    .insertMany(data); 
    response.send(result);
});

// export async function deleteMovieById(id) {
//     return await client
//     .db("crmdata")
//     .collection("sample")
//     .deleteOne({ _id: ObjectId(id)});      
// }

//delete
router.delete("/:name", async function (request,response) {
    const data = request.body;
    console.log(data);

    const result = await client
    .db("client")
    .collection("data")
    .deleteOne({ name: name});
    response.send(result);
    // result.deletedCount > 0
    //     ? response.send({ msg: "List deleted successfully" }) 
    //     : response.status(404).send({ msg: "data not found" });
});

export const dataRouter = router;