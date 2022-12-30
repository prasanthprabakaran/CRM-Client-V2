import mongoose from "mongoose";
// import AutoIncrement from ('mongoose-sequence')(mongoose)

const TaskSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            required: true,
            ref: 'User'
        },
        title: {
            type: String,
            required: true
        },
        text: {
            type: String,
            required: true
        },
        completed: {
            type: Boolean,
            default: false
        }
    },
    {
        timestamps: true
    }
)

// TaskSchema.plugin(AutoIncrement,{
//     inc_field: 'ticket',
//     id: 'ticketNums',
//     start_seq:500
// })

export const Task = mongoose.model("Task", TaskSchema);

export default Task;
