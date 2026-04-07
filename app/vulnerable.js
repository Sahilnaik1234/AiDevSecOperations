// app/vulnerable.js — HIPAA Compliance Test for JavaScript
const logger = require('console');

function processPatientData(patientName, patientSSN, medicalConditions) {
    console.log(`Processing patient: ${patientName}`);
    console.debug(`DEBUG: SSN ${patientSSN} - History: ${medicalConditions}`);

}
