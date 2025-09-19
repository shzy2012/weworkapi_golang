## weworkapi_golang

weworkapi_golang 是为了简化开发者对企业微信 API 接口的使用而设计的，API 调用加解密库之 golang 版本

原项目地址：https://github.com/sbzhu/weworkapi_golang

## 新增功能

新增了 json 格式解析，用于解析企业微信 ai-bot 消息解析

## 使用方法

```go
var wxCPT = wxbizmsgcrypt.NewWXBizMsgCrypt(token, encodingAESKey, "" /*填写空*/)

// 解密json格式消息
reqMsgSign := "424304741b33d9c5a2f2d47d5b7b628f998256e1"
reqTimestamp := "1758262742"
reqNonce := "1758032071"
postData := `{"encrypt":"zyrg060K\/LGlKQw+2oAN4s8+RnjA0gQXaGQw\/JlXAysMvSFDMFIgfFAz2MW4dqZbVbbDsX6pArh5n0VEsXrgglIyF+BcvS0oKFCYQQ4bLr\/P8VAWEvcXhH6TZm17Yvsedso\/NfNCvKrLKgOq7eJ\/ySkWpFYpSulG7M8MKSYaEDvV9KqvC7kDhFNkuZdHQHZR8VDHBa+YIPZ7vcQlZXx2unZgHhdPVajLIVoXuZ562Cxa2zOpzwQFkisAsAZCyG7WqIw5TrQk\/EojlumvbSzofM+zj55kjFB3i3iy4\/5orlE="}`

msg, cryptErr := wxCPT.DecryptJsonMsg(reqMsgSign, reqTimestamp, reqNonce, []byte(postData))
if nil != cryptErr {
	log.Println("DecryptJsonMsg fail", cryptErr)
}

log.Printf("msg: %s\n", string(msg))
```

## 解析结果

```json
{
  "msgid": "e289f069c2be0d73d789d1824ee8e7d1",
  "aibotid": "aib_xxx",
  "chattype": "single",
  "from": {
    "userid": "xxx"
  },
  "msgtype": "text",
  "text": {
    "content": "Hi"
  }
}
```

## Usage

将本项目下载到你的目录，既可直接引用相关文件  
详细使用方法参考[sample.go](https://github.com/sbzhu/weworkapi_golang/blob/master/sample.go)代码
