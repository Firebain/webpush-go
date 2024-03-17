package ece

import (
	"crypto/ecdh"
	"encoding/base64"
	"testing"
)

func tryEncrypt(inSalt string, inLocalKey string, inP256dh string, inAuth string, blockSize int, inData string) (string, error) {
	salt, err := base64.RawURLEncoding.DecodeString(inSalt)
	if err != nil {
		return "", err
	}

	localKeyBytes, err := base64.RawURLEncoding.DecodeString(inLocalKey)
	if err != nil {
		return "", err
	}

	localKey, err := ecdh.P256().NewPrivateKey(localKeyBytes)
	if err != nil {
		return "", err
	}

	p256dh, err := base64.RawURLEncoding.DecodeString(inP256dh)
	if err != nil {
		return "", err
	}

	auth, err := base64.RawURLEncoding.DecodeString(inAuth)
	if err != nil {
		return "", err
	}

	encoder := Aes128GcmEncoder{}

	encrypted, err := encoder.Encrypt(salt, localKey, p256dh, auth, blockSize, []byte(inData))
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func TestEceEncoding(t *testing.T) {
	t.Run("Encrypt ietf rfc", func(t *testing.T) {
		result, err := tryEncrypt(
			"DGv6ra1nlYgDCS1FRnbzlw",
			"yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
			"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
			"BTBZMqHH6r4Tts7J_aSIgg",
			0,
			"When I grow up, I want to be a watermelon",
		)
		if err != nil {
			t.Fatal(err)
		}

		if result != "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN" {
			t.Fatal("Wrong encoded payload", result)
		}
	})

	t.Run("Encrypt hello world", func(t *testing.T) {
		result, err := tryEncrypt(
			"_5Hl49t3uqUCJW0G9uYhdQ",
			"Oa--zmhqBR1emb5QMnIbcWtuIOYNaS9jvRAPIyuXU4s",
			"BC99xnsXypPUFPnSKBxbdWHquFkZPAyGh8XbBrfm7WKul7DGzS7Rd8pkXbAwNUTvqek5OusUSl_mro4tPWSqaik",
			"jmNpi368MwKGAQ234FGXuA",
			DefaultBlockSize,
			"Hello world",
		)
		if err != nil {
			t.Fatal(err)
		}

		if result != "_5Hl49t3uqUCJW0G9uYhdQAAEABBBOjG215zUWgaoINZYtd-hEza4xA6btv2CV-9dVhxKq_NjkVXm044SZpvBBg_YSIAhp7dbGw4g9m14G-vuSoJ9iZpuP2r7Ts_ex-asZ2_GLloj3trrFoa9ndZlGxr5fa2_OgSnLBcT4zGKZ_LM0CV1ASjHhS47Bwis2CL1Ppf5zKXPJPK08ZC2XuiQyX0vyEBGrmc-awUq8tzQIFMu2JngE4DH0IuckE7f7fFHYEVni0gczHb_03GomhKaASt5v8rNLgi2NJSGB6fHZeMX6qJjVg" {
			t.Fatal("Wrong encoded payload", result)
		}
	})

	t.Run("Encrypt json", func(t *testing.T) {
		msg := `[{"id":0,"name":"Daniel","city":"San Diego","age":48,"friends":[{"name":"Charlotte","hobbies":["Quilting","Writing","Music"]},{"name":"Levi","hobbies":["Gardening","Music"]},{"name":"Elijah","hobbies":["Video Games","Writing"]},{"name":"Isabella","hobbies":["Writing","Gardening","Video Games"]}]},{"id":1,"name":"Sarah","city":"Lahaina","age":39,"friends":[{"name":"Mia","hobbies":["Church Activities","Writing","Collecting"]},{"name":"Levi","hobbies":["Television","Team Sports","Tennis"]},{"name":"Kevin","hobbies":["Fishing","Martial Arts"]},{"name":"Victoria","hobbies":["Watching Sports","Video Games","Calligraphy"]}]},{"id":2,"name":"Charlotte","city":"Honolulu","age":49,"friends":[{"name":"Chris","hobbies":["Socializing","Writing"]},{"name":"Victoria","hobbies":["Yoga","Jewelry Making","Woodworking"]},{"name":"Liam","hobbies":["Eating Out","Martial Arts","Video Games"]},{"name":"Ava","hobbies":["Board Games","Team Sports"]},{"name":"Robert","hobbies":["Dancing","Housework","Writing"]}]},{"id":3,"name":"Noah","city":"St. Louis","age":89,"friends":[{"name":"Sarah","hobbies":["Board Games","Woodworking","Skiing & Snowboarding"]},{"name":"Olivia","hobbies":["Quilting","Jewelry Making"]},{"name":"Chris","hobbies":["Writing","Jewelry Making"]},{"name":"Kevin","hobbies":["Eating Out","Genealogy"]}]},{"id":4,"name":"Daniel","city":"San Diego","age":87,"friends":[{"name":"Michael","hobbies":["Genealogy","Fishing"]},{"name":"Noah","hobbies":["Bicycling","Martial Arts","Calligraphy"]}]},{"id":5,"name":"Amelia","city":"Portland","age":57,"friends":[{"name":"Noah","hobbies":["Watching Sports","Cooking","Golf"]},{"name":"Elijah","hobbies":["Church Activities","Tennis","Running"]},{"name":"Kevin","hobbies":["Movie Watching","Gardening"]}]},{"id":6,"name":"Levi","city":"Las Vegas","age":23,"friends":[{"name":"Grace","hobbies":["Bicycling","Watching Sports"]},{"name":"Charlotte","hobbies":["Writing","Reading"]}]},{"id":7,"name":"Noah","city":"Los Angeles","age":76,"friends":[{"name":"Leo","hobbies":["Genealogy","Martial Arts"]},{"name":"Emily","hobbies":["Shopping","Genealogy","Cooking"]}]},{"id":8,"name":"Isabella","city":"Honolulu","age":25,"friends":[{"name":"Sarah","hobbies":["Quilting","Yoga"]},{"name":"Victoria","hobbies":["Bicycling","Cooking"]},{"name":"Evy","hobbies":["Genealogy","Gardening","Bicycling"]},{"name":"Nora","hobbies":["Writing","Team Sports","Martial Arts"]},{"name":"Liam","hobbies":["Calligraphy","Music"]}]},{"id":9,"name":"Leo","city":"Portland","age":56,"friends":[{"name":"Grace","hobbies":["Golf","Eating Out"]},{"name":"Oliver","hobbies":["Cooking","Jewelry Making"]},{"name":"Noah","hobbies":["Walking","Collecting"]},{"name":"Luke","hobbies":["Skiing & Snowboarding","Bicycling"]}]},{"id":10,"name":"Oliver","city":"Branson","age":29,"friends":[{"name":"Emma","hobbies":["Jewelry Making","Martial Arts"]},{"name":"Olivia","hobbies":["Genealogy","Board Games"]}]},{"id":11,"name":"Levi","city":"New York City","age":25,"friends":[{"name":"Charlotte","hobbies":["Martial Arts","Genealogy"]},{"name":"Ava","hobbies":["Podcasts","Woodworking","Shopping"]}]},{"id":12,"name":"Joe","city":"New York City","age":97,"friends":[{"name":"Ava","hobbies":["Music","Writing","Jewelry Making"]},{"name":"Camila","hobbies":["Board Games","Jewelry Making"]},{"name":"Joe","hobbies":["Running","Podcasts"]}]},{"id":13,"name":"Michael","city":"Austin","age":95,"friends":[{"name":"Grace","hobbies":["Church Activities","Shopping"]},{"name":"Oliver","hobbies":["Calligraphy","Skiing & Snowboarding"]}]},{"id":14,"name":"Charlotte","city":"Sedona","age":72,"friends":[{"name":"Sarah","hobbies":["Team Sports","Martial Arts"]},{"name":"Olivia","hobbies":["Running","Gardening"]},{"name":"Robert","hobbies":["Jewelry Making","Dancing"]},{"name":"Daniel","hobbies":["Painting","Skiing & Snowboarding"]},{"name":"Jack","hobbies":["Shopping","Reading"]}]}]`

		result, err := tryEncrypt(
			"6snAxmUCQd1q_X2P4-2Cow",
			"usEk3Ph2B57q1BxIBrQNNr6Hw3ky6aihPVWe0D2y0SE",
			"BCJs1KUMpjdWXaUqM6fyF7KoFIe-L6vRZ32m-8rD4DOI-h0-T0PjSyoGyEAcD-PhXY9yD5tNeJvvHB0yGo9DLKA",
			"6VW-aNVu_2H-V3ye0fu9fg",
			DefaultBlockSize,
			msg,
		)
		if err != nil {
			t.Fatal(err)
		}

		if result != "6snAxmUCQd1q_X2P4-2CowAAEABBBCYo0TFws7eTvTgwaTbkgWC-pQ5-oOf1KVWz8UozX-C8m7ad0AK9XOpRX2Ze-NWxSBE4A5kwOICf4hnUlw8gf7t0M5e5cbz2gmQhpbQ3bPdFrWI5RfJPHL8_7UpoyawHOdBQoQpeCcS4bcCVDE6udvag1lWQrycTw19e2_0ZVwDMH5_fy2rWwaGsXcR0SWwcqc3Tg0rostvWPa22WT8u_6OoJSy_Ed-rauY7iZ9cNV8lGcK87bjqfxoyqaGxuUZOBUAQSWgQSp3cCKmusLqfMwgspwrrWpaN_64ueijKJAAui3-rIMbMMEbvzLsCTsnZ9mFrOkg2w8YIdagDNOvOqYzbhO6uXW7My0AZ3AsuZ1YycZtFy-TWYCZ7k7qDHP8Egmd5s6LZtdEt_uPOV7e_OGL72Msq0wAdbpQKEelmTS-a5V8cc4eu-LZj-qacmxh3KB-GHzBiAGJuOx7dEL4EAbxIcDz_U_4lZNeKVRK3H90ioNfccJU6ZYV9jNPcKwPmkCRSCv0EHwyRDIXtcdDg_4Za9mIY8rC2DN_nH_t_SblyT5QkI3a5UartremK6C0iFIlTr1NvqQoAZeLOBPwz7NHjKozuCKVHUUHugGK-bXh_PJb4fgymh4Z2GdekiaEICEuBT3u33Bikb6wH9aSFhJdULvADv97-thN0z8iyK_uYES1ZCiV9q5_60Htq3qxXJWMo8m_Mjs2KogzycrwyqTTSKM_ZIbqB2koaanHvMfCId50PfFkMdtAXagKxwpUkEE5sfvYLHc_z5S4gfIv3oDIV4kJu48r2KbgIw_S0pDYGHM7Bz9Q7FUIrxbjdcez4sXHfbIHWzjalqD6F_2dyofvdIchA5aObNgRQogwjwtgV965iVMRZKFzZziTfnoDXH-2EwDj9yG2cBwTymFvckJc-iSrCFl-fqkV32O4fTz484wSkSgR2PgPDNZQwsqZ6MdyjU0Wj00vAscV1xe-4rLY_vbEWJSMmLee3dxlm9v6JMDk6i2FTBSXzvCJ7TkBc3M9N_7atXbdw11_yZspvqT0RI2qwqXIiSyOw6KrOQRgHWnJ3ih1SfOHQyRxfJanAoEFeJX7P_WR3wyt3FjYk35vEVIX8jFMYe__6RoNfsB_L6hGIojQ-W3b4HkwvPb-l8nV2kSL3x5eWBlrAPFhQd71if_NYenFtqkIzKGblLHOH8c5NPKqx8plKmdc-GpzOX8ZohYXgTPKNw_j0NYoj1jMA_ehsnjiVmZJSccU3A-FG1L2GGrXf83-HdCdM5JMXuobkhGevMJrpTdmpr1xVSs4WEFPEfLmuvmOxKUKT6t0_d2mNOKlzjjnSq_oVnsGcnsw17nNiC2IuCDszlXBNQfa_6py0ko9YtU2mVVKZRJAQ8Z0C1kEadE2t7zAvCdijk-59Bkk0ZrH1nKvxLPBo0Zbjit2fzmo3XlDnesk66Es4zyGIMEg6toRffEFzm46HbcC9knTD1Kbwym7zNEFP3sHsQln6fnJS944l8c9Wo84bG18ozW_hIlP3CmmQlCeSJ7EnoJ6mWmfyQSlHEARCGWeHO2aV5DvXQP_Jw_FKBk63dhY6J_nAQuZRXaQQbTfUxPClLYvv9qsSaI5G8X8KjgUF0SAuTkOv64Gm16DyLIbXA-06V6oX4LitxwKBuCp8Gyz0-eB9XZcb2Yi-JXXqs61lFv7qm-S0ODSdu4XgN8IHXESQ_dycXwh61lkaELq6QsaBWmXMTkzcsBC1I6B_WbtwFFzdlHeBpyM3EWeetanYuhUMjQG3P8JzFjGBB5jonWA8on2aHNXLBQhtJo0tLVWi8ctN_Si2VVVGOR-sejf-zOAcZMuwphcNFzp6d4U0T7dMne-1GHIWf4NI6xct9gyPfUmET3lU8px1u7LN4d2_9ZWfejwSnX8TfMaQFB0vX_1sEFT4Fd-bp_l7j--J5Cqf_fOuQ7OhbysNdqFmUxnNtcW_SV0wEbG5RzGDdkrSdREiGfoRig7I7mLtxsmScPTs6QmZzIP8J4-M1pMjJkvmMnRRqOOVKHxvOLwgFZ5SK71C_2qZlnFPnyyv7Q2URHJvZ7IBgvGXiJqS3XIPe4FXlLvGWKa7qTdg_fjXXRymE8N_1chy7B9YcaVFy6RNeVdVqreXtOY-KK9XkvUJdeJpwpS85kC9kPsZFCVPDm21ai-gn5juRGd2_3ElwjB7fHay3h4HkjImspRs_USD3cLmJHcpSE-Eer1ESPpHX6kLYrTU8qOjRY_0mu9SR_PgJ2luXsuuaFKfySX1mUe93oT1cj0f75zekQnJFalkcpPKr_GrbfAvgwnDyCgmXE9rVKuv6rFvxTMEQFTXGUu8SSgRl8FCizy7eii1CrA9oDhDRkEDmQk3lkxDajjU20af7vIhqL6IJX6A0KtJUTtBPrGq6huTYXbfqIe47dngflvd3AqyJHT1vAEXoNGEponQ7n8RVu3W8kmW9OXIU8MFDsS8Lv4t5EB7dAJXQ93JDcRzYtuQ2c7ye9Jt2Yd86xisRge0Y8qz9DSqEcoNEZpgPn-_kt8Ij0_SwBghXNzdDYDUMh9g5EXJ6sPrkNZE6wNj9JitrpoTNKHuCKbT8h1ELrXXCaObtGDBu2gfBiec2RuEyonCAHojLxsMsHvT8XHeB8YCHXCfO2yNaffQGHF9Zj17m10NrhDSLAeAu_5OIxZd_A-1eXVecOFi6D15tepquLjAZrrUjQDGdrFpot43bZ4csS5cFdEoFdFX82cfuMI_uNahFONtIPlSK6eNGZT2bvqgpaWXo467Nj-w96m5yNt5qmtGJIpPl03TlXrXVXQxca7QDekwNqphFkWh14E9sz8QGniSozmyia089Q3FyIuLA13W5KSQ0wrfG6Ldgme3TYDYjAvfXeso8S8NtRlr8zc7yZXun30d-ulfFqZ9qXvovUmvKbd6d5z7LQr4VIZxpeLOpjpwoEAHuEU8xRiabVFp82H48lWWvnJJ0QQ4EI6E5n0RAn1gfwrYlRjTflRjmwIqt5y0S1-s-JrLCDtEFojM1YQ41vCE8wUuR7QCfghpf43c_U6iWLk3VjeV-mlOa3h8DLgL9GCAP33LfgYpL-iTdWjzHAktsWk6UVLx3S1JIc2HH6kbl_WLNAZMj-B1lPDtUHSaNaXXyvXWMQzNIaRho4WZnW5xUkp2OaGNpYb6TozKr6wyasYvxfm5cGxlOCX5zcOHkZ5MeEWFW04_6Ca9-c1ER9v_W0QSPcGJj1QAXjeYbSjKdofDyGLghcxbZO0U5yhJmnbCK1RAp5HfTx1YYTpRhiWdXVeIzdGJA956c8QGZ9U3nW-C9LzDDJXSI300U17hb1R8fvgWg1EgN6GetzGTXMiq5ypXvNC6FWD_I0P02AlStxtzMNydZaI0Lihqeyx6iLr3BsrcXU7Je7sJRGYcoJmybCqupT8ZMj1lor0Whmsu-onITH6NBTNEfvu6jNxMK245TibotUKQnib8egzy1VbmyFIcM3KqxzFasgexXkpz79AYGgSISdY8unaZ6i0UZ93dKWy773o1vrnmIup3yauVOD06j0_bYpHYgFFPjAhlo8AuH7cwSFb3J1CHgTw-qrJNe1LvLbH9duyg2MD44ZxjYWO3h8yypH1FC7fW75h6DFGXAJkeJ5uZivwYlA3endn94wbiVMPvlK3Ndhjplxi8ocrW4NGczoNuJ1R5122YML9-2gZJjOXsZQ47uiZTNHVUisQ29Jy8EvO9Pnj3c-fyBnCd5uJRzsttAYWzCIprLPqaW6rFTO4PsmtGBGJW4uTqIpA9wMj749OS0mudWM4LVLLOtVYAy8bcjqH0k8vykelDWoLjH61R7mdAfxXHaGp2ojrrDq-h-vsiRq8-wnTxdorbLQelcUghRqm323khMqc0g_Uevxj1PRFu_ivBvm156im2SYnwMaDr4lyzzu-r0lrm8mTil1WXYlmijKDJYfnXXkBXinD5RQYvlqNjTR6ydKizAYJkwoSnDQvFrLlCPW4WM0ZV-A1l2TSEO10_l7W_piiufPBynsxILbuftjDRkCZnACjtWPwnlNJzW_RtRFOZMJLnGOdrplVeduUqhcVhVIs1YalGncUZ0x1TVc2V7G2RMJ3E3INqMplxa0OqD3MZ0HmfcjCJGVwveqXBmNUldxrjbQg91tt3_oBVXLkmEdklmJIj7wZVph7c5PLr5lbsUPRM1HV_Km0yH8GKfi-ZDyh8YgDNNnWLDZ1P97pDnCLqxihuJqielKysRL3vTe_GtqFbClfnfKYvOmmdNdVSpJ0zEp4vwxEfp25evnn1bYPTQ2ghAHYx7_QkL14K_s-VyWa2EBBltoHM9QWtFybqO3EW6Lw9MYAZ0PgZZP1swYpsYlWB1gXnLpG1lTu78_Sx6OZAAnB2QsEbJaYa5dSG9F4LSd00C53a61Fb-7igroozlGwApbVdq7no7_Mpa5XfjgRqqN0zvvC7d6PEIq-z-9cpG7-dZHpb5AEWVkOSNX_inwcKnLtfP9RFOkaYLafkEoE_eqM2iz5ipj-prDw-Hb3edocahP6SDEs2Po8lk1LXySym7v9AldiCDyI2FQWcgbCo9fIumteZp261tOHKyEcYUjH8OJVsLfD-qync51k2bslO8ujL_u_mKCj2AAv5pfFYIpV4K1L9TqgczbAWm-Q0V-o6NAPpitAO-7s2hAsLq9gctmGF5dvI0CiRMChklYBhco9_lxOxv1gjNNMu_5ylHXlsNOa83QmSesMaBQyPPXaWGlMxewNop7QZoElYxDD4ih_ekX5GKM50B8jfNUGZWWFRT7nWLaIxY2MPuUTIl7gRo6lSM5ov7p9X72htLX6Jv2v-pTw8_xKzmjYnn_e18fUVDmXMBr_Hf-TAtjkZWiMmM6HkjIuzlQ_2Owy6Vv8KTZ4Xgrs5i4AK4sL5MK-rNphB5QXF5UdqrELq5AyRVXskXnlXHEAydPOZpf8Ztk8HpFSzYzR_izVMVLy5J03lVYfZSdBWAQbXPoH3Mo7kCItzT0X777HJhv_rjCKS-U8EUukyC4mCn6LT0D4Be2Pez_wde_UNkzpZp-OevGIhde039gDwNf3lSO4gurRAAHnBgTd9ZRrVtIWHybb3gp-FY1vSEPzPBg-xiNJioHJBrTeZ7ojviwELlinT7hhfHR9skyrDzBjCXXHJb0mpe0S1aEXTMsN1TtEXzS4sjEAxlw2u5hqvnYtg7q3E3iiMfw1Z3-USqdz2MatktU6EnRa5eyS1E7-6OsUr7ytV5NILi4JAGOerF4rr47kYWYQ6tzwvL2JXnZBQVwkN2bNKCg6KXQ8FbnP9VCvMSZDdv30W7Cer0vO7PWewHi23rF_DsELZUgKKFRvLE1_ob-bk4wtmLE1JsF7uWihgXUQaBPN7ASyqZC0" {
			t.Fatal("Wrong encoded payload", result)
		}
	})
}
