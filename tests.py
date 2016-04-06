"""
Rather then twidder, should import whatever your project's main file is

Current problems:
    - Cross runs can spawn a "user already registered" problem
    - No specifications regarding database field max size may cause issues when running tests for some students?
    - Should a test test that some method works with post and doesn't work with get (or vice-versa) at the same time?

delete from post where author in (select id from user where email like "%legion%");
delete from user where email like "%legion%";
"""
import twidder
import os
import unittest
import tempfile
import json
import random


class TestServerAuthenticationMethods(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up our dummy user's info
        """
        cls.user_info = dict(email="fiery_archy@burninglegion.net", password="thetrueeredar", firstname="Archimonde",
                             familyname="the defiler", gender="male", city="Mac'Aree", country="Argus")

    def setUp(self):
        self.db_fd, twidder.app.config['DATABASE'] = tempfile.mkstemp()
        twidder.app.config['TESTING'] = True
        self.app = twidder.app.test_client()
        # todo:  Hard-coded for my own project, change it.
        twidder.db.create_all()

    def testSignUp(self):
        """
        Description: Registers a user in the database
        Input: Seven string values representing the following: e-mail, password, firstname, familyname, gender, city and country
        :return string in JSON format with success and message :
        """
        response = self.app.get('/sign_up/', query_string=self.user_info)
        # Is this ok? What if the students "accept" the get method but have their own custom method of denying it?
        self.assertNotEqual(response.status_code, 200)

        response = self.app.post('/sign_up/', data=self.user_info)
        self.assertEqual(response.status_code, 200)
        jsoned_response = json.loads(response.data)
        self.assertTrue(jsoned_response['success'])

    def testSignIn(self):
        """
        Description: Authenticates the username by the provided password
        Input: Two string values representing the username (e-mail address) and password

        Returned data: A text string containing a randomly generated access token if the authentication is
        successful.
        :return A text string containing a randomly generated access token if the authentication is successful:
        """
        response = self.app.get('/sign_in/', query_string={'email': self.user_info['email'], 'password': self.user_info['password']})
        self.assertNotEqual(response.status_code, 200)

        response = self.app.post('/sign_in/', data={'email': self.user_info['email'], 'password': self.user_info['password']})
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.data)
        self.assertTrue(response['success'])
        self.assertTrue("token" in response['data'])

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(twidder.app.config['DATABASE'])


class TestServerAuthenticatedMethods(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up our dummy user's info
        """
        cls.user_info = dict(email="@burninglegion.net", password="thetrueeredar", firstname="Archimonde",
                             familyname="the defiler", gender="male", city="Mac'Aree", country="Argus")
        cls.used_mails = [""]

    def setUp(self):
        """
        Set up a new account for this test and proceeds to sign in
        """
        self.db_fd, twidder.app.config['DATABASE'] = tempfile.mkstemp()
        twidder.app.config['TESTING'] = True
        self.app = twidder.app.test_client()
        # todo:  Hard-coded for my own project, change it.
        twidder.db.create_all()

        letters = "abcdefghiklmnopqrstuvwwxyz"
        email_name = ""
        while email_name in self.used_mails:
            t = ""
            for i in range(5):
                t += letters[int(random.random() * len(letters))]
            email_name = t
        self.user_info["email"] = "%s%s" % (email_name,  self.user_info["email"])
        self.used_mails.append(email_name)

        r = self.app.post('/sign_up/', data=self.user_info)
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.data)
        self.assertTrue(response['success'])
        r = self.app.post('/sign_in/',
                          data={'email': self.user_info['email'], 'password': self.user_info['password']})
        self.assertEqual(r.status_code, 200)

        response = json.loads(r.data)
        self.assertTrue(response['success'])
        self.assertTrue("token" in response['data'])
        self.token = response['data']['token']

    def testChangePassword(self):
        """
        Description: Changes the password of the current user to a new one
        Input:
            - token: A string containing the access token of the current user
            - oldPassword: The old password of the current user
            - newPassword: The new password
        :return string in JSON format with success and message :
        """
        # Request password change to server
        r = self.app.get('/change_password/',
                         query_string=dict(token=self.token, old_password=self.user_info['password'], new_password="longlivesargeras"))
        self.assertNotEqual(r.status_code, 200)

        r = self.app.post('/change_password/',
                          data=dict(token=self.token, old_password=self.user_info['password'], new_password="longlivesargeras"))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.data)
        self.assertTrue(response['success'])

        # Make sure the new password is the one used to sign in now
        r = self.app.post('/sign_in/', data={'email': self.user_info['email'], 'password': "longlivesargeras"})
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.data)
        self.assertTrue(response['success'])

    def testSignOut(self):
        """
        Description: Signs out a user from the system
        Input: A string containing the access token of the user requesting to sign out
        :return:
        """
        r = self.app.get('/sign_out/',
                          query_string=dict(token=self.token))
        self.assertNotEqual(r.status_code, 200)
        # sign_out(token)
        r = self.app.post('/sign_out/',
                          data=dict(token=self.token))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.data)
        self.assertTrue(response['success'])

        r = self.app.get('/get_user_data_by_token/',
                         data=dict(token=self.token))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.data)
        self.assertFalse(response['success'])

    def testGetUserDataByToken(self):
        """
        Description: retrieves the stored data for the user whom the passed token is issued for. The currently signed
        in user can use this method to retrieve all its own informatiom from the server
        Input: A string containing the access token of the current user
        :return A text string containing the following information- email, firstname, familyname, gender, city and country:
        """
        r = self.app.post('/get_user_data_by_token/',
                          data=dict(token=self.token))
        self.assertNotEqual(r.status_code, 200)

        r = self.app.get('/get_user_data_by_token/',
                         query_string=dict(token=self.token))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.data)
        self.assertTrue(response['success'])
        # todo: Is this enough to assert that this response is ok, or do we want to check each key
        self.assertEqual(len(response['data']), 6)

    def testGetUserDataByEmail(self):
        """
        Description: Retrieves the stored data for the user speciied by the passed e-mail address
        Input:
            - token: A string containing the access token of the current user
            - email: The email address of the user to retrieve data for
        :return A text string containing the following information- email, firstname, familyname, gender, city and country:
        """
        r = self.app.post('/get_user_data_by_token/',
                          data=dict(token=self.token, email="fiery_archy@burninglegion.net"))
        self.assertNotEqual(r.status_code, 200)

        r = self.app.get('/get_user_data_by_token/',
                         query_string=dict(token=self.token, email="fiery_archy@burninglegion.net"))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.data)
        self.assertTrue(response['success'])
        self.assertEqual(len(response['data']), 6)

    def testGetUserMessagesByToken(self):
        """
        Description: retrieves the stored messages for the user whom the passed token is issued for. The currently signed in
        user can use this method to retrieve all its own messages from the server.
        Input: A string containing the access token of the current user.

        :return A text string containing all of the messages sent to the user:
        """
        # todo: post message here first
        r = self.app.post('/get_user_messages_by_token/',
                          data=dict(token=self.token))
        self.assertNotEqual(r.status_code, 200)
        r = self.app.get('/get_user_messages_by_token/',
                         query_string=dict(token=self.token))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.data)
        self.assertTrue(response['success'])

    def testGetUserMessagesByEmail(self):
        """
        Description: Retrieves the stored messages for the user specified by the passed e-mail address
        Input:
            - token: a string containing the access token of the current user
            - email: the e-mail address of the user to retrieve messages for
        :return A text string containing all of the messages sent to the specified user:
        """
        r = self.app.post('/get_user_messages_by_email/',
                          data=dict(token=self.token, email="fiery_archy@burninglegion.net"))
        self.assertNotEqual(r.status_code, 200)

        r = self.app.get('/get_user_messages_by_email/',
                         query_string=dict(token=self.token, email="fiery_archy@burninglegion.net"))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.data)
        self.assertTrue(response['success'])

    def testPostMessage(self):
        """
        Description: tries to post a message to the wall of the user specified by the e-mail address
        Input:
            - token: a string containing the access token of the current user
            - message: The message to post
             - email: the e-mail address of the recipient
        :return:
        """
        r = self.app.get('/post/',
                         query_string=dict(token=self.token, email="fiery_archy@burninglegion.net", message="For the legion!"))
        self.assertNotEqual(r.status_code, 200)

        r = self.app.post('/post/',
                          data=dict(token=self.token, email="fiery_archy@burninglegion.net", message="For the legion!"))
        self.assertEqual(r.status_code, 200)
        response = json.loads(r.data)
        self.assertTrue(response['success'])

    @classmethod
    def tearDownClass(cls):
        # todo: Delete users somehow
        pass


def custom_suite():
    suite = unittest.TestSuite()
    suite.addTest(TestServerAuthenticationMethods('testSignUp'))
    suite.addTest(TestServerAuthenticationMethods('testSignIn'))

    # suite.addTests(unittest.makeSuite(TestServerAuthenticatedMethods))
    suite.addTest(TestServerAuthenticatedMethods('testChangePassword'))
    suite.addTest(TestServerAuthenticatedMethods('testGetUserDataByToken'))
    suite.addTest(TestServerAuthenticatedMethods('testGetUserDataByEmail'))
    suite.addTest(TestServerAuthenticatedMethods('testSignOut'))
    suite.addTest(TestServerAuthenticatedMethods('testPostMessage'))
    suite.addTest(TestServerAuthenticatedMethods('testGetUserMessagesByToken'))
    suite.addTest(TestServerAuthenticatedMethods('testGetUserMessagesByEmail'))

    return suite

mySuit = custom_suite()

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(mySuit)