use rand_core::{RngCore, CryptoRng, OsRng};

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, constants::ED25519_BASEPOINT_POINT};
use crate::helpers::{hash, random_scalar, random_edward_point};
use crate::signature::*;

pub struct knowledge_elements {
    w: Vec<EdwardPoint>,
    h: EdwardPoint,
    pub H: EdwardPoint,
}

impl knowledge_elements {
    pub fn set_w(&mut self, my_singning_pub: &EdwardsPoint, his__signing_pub: &EdwardsPoint, auths_pub: &Vec<EdwardsPoint>) {
        if auths_pub.len() == 3 {
            self.w = Vec::new();
            self.w.push(my_singning_pub.clone());
            self.w.push(his__signing_pub.clone());
            for auth in auths_pub {
                self.w.push(point.clone());
            }
        }
        else{
            //gérer l'erreur 
            println!("auths_pub doit contenir exactement 3 clés");
        }
    }

    pub fn set_h(&mut self,auth1_pub: &EdwardsPoint, auth2_pub: &EdwardsPoint, auth3_pub: &EdwardsPoint){
        self.h = auth1_pub.clone() + auth2_pub.clone() + auth3_pub.clone();
    }

    pub fn set_H(&mut self, my_message_priv: &Scalar, his_message_priv: &EdwardPoint){
        self.H = my_message_priv.copy() * (self.h + his_message_priv);
    }
}


pub trait Sign_of_knowledge {
    /// Sign a message and returns a `Signature`
    fn knowledge(&self, his_message_pub: &EdwardPoint, my_message_pub: &EdwardPoint, my_message_priv: &EdwardPoint) -> Signature;
}

impl Sign_of_knowledge for knowledge_elements {
    fn singKnowledge(&self, his_message_pub: &EdwardPoint, my_message_pub: &EdwardPoint, my_message_priv: &EdwardPoint) -> Signature{
        let r = random_scalar(OsRng);
        let R1 = random_edward_point(r);
        let h_plus_his = self.h.clone() + his_message_pub;
        let R2 = r * h_plus_his;
        let mut digest = vec![R1, R2, ED25519_BASEPOINT_POINT, h_plus_his, my_message_pub, self.H, self.w];
        let c = hash(digest);
        let z = r + c*my_message_priv;
        Signature { c, z}
    }
}