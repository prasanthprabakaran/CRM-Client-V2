import Joi from 'joi'

export const createTaskSchema = Joi.object({
    user: Joi.string().required().messages({
        'string.empty': 'User ID is required',
        'any.required': 'User ID is required'
    }),
    title: Joi.string().required().messages({
        'string.empty': 'Title is required',
        'any.required': 'Title is required'
    }),
    text: Joi.string().required().messages({
        'string.empty': 'Text is required',
        'any.required': 'Text is required'
    })
})

export const updateTaskSchema = Joi.object({
    user: Joi.string().required().messages({
        'string.empty': 'User ID is required',
        'any.required': 'User ID is required'
    }),
    title: Joi.string().required().messages({
        'string.empty': 'Title is required',
        'any.required': 'Title is required'
    }),
    text: Joi.string().required().messages({
        'string.empty': 'Text is required',
        'any.required': 'Text is required'
    }),
    completed: Joi.boolean().required().messages({
        'any.required': 'Completed status is required',
        'boolean.base': 'Completed must be a boolean'
    })
})