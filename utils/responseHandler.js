const sendSuccess = (response, data = {}, message = 'Request succesful') => {
  const resp = {
    data,
    message,
    status: 'success',
  };
  return response.status(200).json(resp);
};

const sendError = (response, errors = [], message = 'Invalid requests', code = 422) => {
  const resp = {
    errors,
    message,
    status: 'failed',
  };
  return response.status(code).json(resp);
};

module.exports = { sendSuccess, sendError };
