import Joi from 'joi'

export const createUserSchema = Joi.object({
    username: Joi.string().required().messages({
        'string.empty': 'Username is required',
        'any.required': 'Username is required'
    }),
    firstname: Joi.string().required().messages({
        'string.empty': 'First name is required',
        'any.required': 'First name is required'
    }),
    lastname: Joi.string().optional().allow(''),
    email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email',
        'string.empty': 'Email is required',
        'any.required': 'Email is required'
    }),
    password: Joi.string().min(6).required().messages({
        'string.min': 'Password must be at least 6 characters',
        'string.empty': 'Password is required',
        'any.required': 'Password is required'
    }),
    roles: Joi.array().items(Joi.string()).optional()
})

export const updateUserSchema = Joi.object({
    username: Joi.string().required().messages({
        'string.empty': 'Username is required',
        'any.required': 'Username is required'
    }),
    roles: Joi.array().items(Joi.string()).min(1).required().messages({
        'array.min': 'At least one role is required',
        'any.required': 'Roles are required'
    }),
    active: Joi.boolean().required().messages({
        'any.required': 'Active status is required',
        'boolean.base': 'Active must be a boolean'
    }),
    password: Joi.string().min(6).optional().allow('')
})