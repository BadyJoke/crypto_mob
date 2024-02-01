use rand_core::OsRng;

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, constants::ED25519_BASEPOINT_POINT};
use crate::helpers::{hash, random_scalar, random_edward_point};
use crate::signature::*;

pub struct KnowledgeElements {
    pub w: Vec<EdwardsPoint>,
    pub h: EdwardsPoint,
    pub big_h: EdwardsPoint,
}

impl KnowledgeElements {
    pub fn new(w: &Vec<EdwardsPoint>, h: EdwardsPoint, big_h: EdwardsPoint) -> Self {
        KnowledgeElements {
            w : w.clone(),
            h,
            big_h,
        }
    }

    pub fn set_w(&mut self, my_singning_pub: &EdwardsPoint, his_signing_pub: &EdwardsPoint, auths_pub: &Vec<EdwardsPoint>) {
        if auths_pub.len() == 3 {
            self.w = Vec::new();
            self.w.push(my_singning_pub.clone());
            self.w.push(his_signing_pub.clone());
            for auth in auths_pub {
                self.w.push(auth.clone());
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

    pub fn set_big_h(&mut self, my_message_priv: &Scalar, his_message_priv: &EdwardsPoint){
        self.big_h = my_message_priv* (self.h + his_message_priv);
    }
}


pub trait SignOfKnowledge {
    /// Sign a message and returns a `Signature`
    fn sign_knowledge(&self, his_message_pub: EdwardsPoint, my_message_pub: EdwardsPoint, my_message_priv: &Scalar) -> Signature;
}

impl SignOfKnowledge for KnowledgeElements {
    
    fn sign_knowledge(&self, his_message_pub: EdwardsPoint, my_message_pub: EdwardsPoint, my_message_priv: &Scalar) -> Signature{
        let r = random_scalar(OsRng);
        let r1 = random_edward_point(r);
        let h_plus_his = self.h.clone() + his_message_pub;
        let r2 = r * h_plus_his;
        let mut digest = vec![r1, r2, ED25519_BASEPOINT_POINT, h_plus_his, my_message_pub, self.big_h];
        digest.append(self.w.clone().as_mut());
        let c = hash(digest);
        let z = r + c*my_message_priv;
        Signature { c, z}
    }
}