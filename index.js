import express from "express";
import crypto from "crypto";
import cors from "cors";

const app = express();

app.use(express.json());
app.use(cors());

app.post("/", (req, res) => {
  const {option, inputParams, CMValgorithm, HashKey, HashIV} = req.body;
  const AESAlgorithm = "aes-128-cbc";

  if (option === 0) {
    let parsedInput;
    let CMVStep1;

    if (inputParams.includes("{" && "}")) {
      try {
        parsedInput = JSON.parse(inputParams);
        CMVStep1 = Object.entries(parsedInput)
          .sort(([keyA], [keyB]) => keyA.localeCompare(keyB))
          .map(([key, value]) => `${key}=${value}`)
          .join("&");
      } catch (error) {
        const fixedInput = inputParams
          .replace(/(\w+):/g, '"$1":')
          .replace(/,\s*}$/, "}");
        parsedInput = JSON.parse(fixedInput);
      }
    } else {
      function parseAndSortParams(inputParams) {
        // 使用正則表達式來分割參數，但保持引號內的內容完整
        const params = inputParams.match(
          /(?:[^&=]+(?:=(?:[^&"]*(?:"[^"]*")?[^&"]*)+)?)/g
        );

        // 解析每個參數
        const parsedParams = params.map(param => {
          const [key, ...valueParts] = param.split("=");
          const value = valueParts.join("="); // 重新組合可能包含 = 的值
          return [key, value];
        });

        // 排序參數
        parsedParams.sort(([keyA], [keyB]) => keyA.localeCompare(keyB));

        // 重新組合成字符串
        return parsedParams.map(([key, value]) => `${key}=${value}`).join("&");
      }

      CMVStep1 = parseAndSortParams(inputParams);
    }

    const CMVStep2 = `HashKey=${HashKey}&${CMVStep1}&HashIV=${HashIV}`;
    const CMVStep3 = DotNETURLEncode(encodeURIComponent(CMVStep2));
    const CMVStep4 = CMVStep3.toLowerCase();
    const CMVStep5 = crypto
      .createHash(CMValgorithm)
      .update(CMVStep4)
      .digest("hex");
    const CMVStep6 = CMVStep5.toUpperCase();
    const response = `
<pre>
    檢核碼計算順序
  (1) 將傳遞參數依照第一個英文字母，由A到Z的順序來排序(遇到第一個英名字母相同時，以第二個英名字母來比較，以此類推)，並且以&方式將所有參數串連。
  ${CMVStep1}

  (2) 參數最前面加上HashKey、最後面加上 HashIV
  ${CMVStep2}

  (3) 將整串字串進行URL encode
  ${CMVStep3}

  (4) 轉為小寫
  ${CMVStep4}

  (5) 以 ${CMValgorithm} 方式產生雜凑值
  ${CMVStep5}

  (6) 再轉大寫產生 CheckMacValue
  <span class="toCopy">${CMVStep6}</span>
</pre>`;

    res.send(response);
  } else if (option === 1) {
    //特殊字元編碼後英文為大寫時
    let URLEncoded = encodeURIComponent(inputParams);
    const cipher = crypto.createCipheriv(AESAlgorithm, HashKey, HashIV);
    let EncryptedData = cipher.update(URLEncoded, "utf8", "base64");

    EncryptedData += cipher.final("base64");

    const response = `<pre>
(1)加密前 Data 資料：
${inputParams}

(2)URLEncode 編碼後結果：
${URLEncoded}

(3)AES 加密後結果：
<span class="toCopy" >${EncryptedData}</span>
</pre>`;

    res.send(response);
  } else if (option === 2) {
    const decipher = crypto.createDecipheriv(AESAlgorithm, HashKey, HashIV);
    let DecryptedData = decipher.update(inputParams, "base64", "utf8");
    DecryptedData += decipher.final("utf8");

    const response = `<pre>
      (1)AES 解密前 Data 資料：
      ${inputParams}

      (2)AES 解密後 Data 資料：
     <span class="toCopy"> ${decodeURIComponent(DecryptedData)} </span>
</pre>
      `;

    res.send(response);
  } else {
    res.status(400).send("無效的選項");
  }
});

function DotNETURLEncode(string) {
  const list = {
    "%2D": "-",
    "%5F": "_",
    "%2E": ".",
    "%21": "!",
    "%2A": "*",
    "%28": "(",
    "%29": ")",
    "%20": "+"
  };

  Object.entries(list).forEach(([encoded, decoded]) => {
    const regex = new RegExp(encoded, "g");
    string = string.replace(regex, decoded);
  });

  return string;
}

const port = 3000;
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

// 部署到 Vercel 需要增加這一行
//export default app;

//1. 有前後端有很多問題
//2.  input 輸入的都是 string
//3.
