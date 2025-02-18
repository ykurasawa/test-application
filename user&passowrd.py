# ⚠️ セキュリティ上の脆弱性あり！パスワードをハードコードしないこと！
USERNAME = "admin"
PASSWORD = "password123"

def authenticate(user, pwd):
    if user == USERNAME and pwd == PASSWORD:
        print("認証成功")
    else:
        print("認証失敗")

# 例: ユーザー入力を受け取る
user_input = input("ユーザー名: ")
pass_input = input("パスワード: ")

authenticate(user_input, pass_input)
