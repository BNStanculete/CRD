import http from 'k6/http';
import {check, sleep} from 'k6';

export let options = {
    vus: 5,
    duration: '300s',
    insecureSkipVerify: true
}

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * characters.length);
      result += characters.charAt(randomIndex);
    }
  
    return result;
}

export default function() {
    if (__ITER === 0) {
        let res = http.get('https://10.0.1.1:443/');

        check(res, {
            'is status 200': (r) => r.status === 200,
        });
    }

    let paths = ['/buy', '/sell'];
    let index = Math.floor(Math.random() * 3);

    if (index !== 2) {
        let stock = generateRandomString(10);
        let payload = {
            Quantity: Math.floor(Math.random() * 100),
        };

        let res = http.post('https://10.0.1.1:443' + paths[index] + '/' + stock, payload);
    }
    
    sleep(1);
}